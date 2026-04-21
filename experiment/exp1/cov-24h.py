#!/usr/bin/env python3

"""
串行 fuzz 管理脚本（Watchdog 模式）。

1) 读取 status.json：
	- to_fuzz：待 fuzz 的服务名或服务目录路径。
	- config：check_interval / stall_minutes / results_root / max_duration_hours 等。
2) 为每个服务生成“隔离版”运行目录：
	- 复制 service.json、corpus（以及可选的 check_result.json）。
	- 复制一份并重写 run.sh：
	  - 把相对路径改为绝对路径；
	  - 固定 -out 到隔离目录；
	  - 固定 -nthreads=1；
	  - 统一 DYLD_INSERT_LIBRARIES 路径；
	  - harness 路径改为绝对路径。
3) 启动 fuzz（Jackalope）并监控：
	- 每 check_interval 秒解析 fuzz.log；
	- 以 Offsets 增长作为“活跃”指标；
	- 若 stall_minutes 分钟 Offsets 无增长则停止；
	- 若设置 max_duration_hours，超过时长则停止；
	- 将解析到的统计项写入 coverage_history.jsonl。
4) 持续更新 status.json：
	- fuzzing / fuzzed / fuzzing_detail；
	- 记录路径、时间戳、语料数量、覆盖率历史与停止原因。

【注意事项】
1) 必须 sudo 运行（需要 root 权限）。
2) 不依赖 litecov（已弃用），全部指标来自 fuzz.log。
3) 服务目录需包含：
	- run.sh（能找到 coreaudiofuzzer 的启动命令）；
	- service.json（必需）；
	- corpus（推荐）；
	- check_result.json（可选：用于限制有效消息 ID）。
4) 隔离目录的结构固定在 results_root/<date>/<service_name>/ 下；日志与覆盖率历史也在这里。

【假设】
1) run.sh 中存在一行包含 coreaudiofuzzer 的启动命令，且参数格式符合解析逻辑。
2) -instrument_module、-target_env(DYLD_INSERT_LIBRARIES)、-- harness 参数存在且可解析。
3) 语料增长可以用 out 目录文件数量变化来判断。
4) check_result.json 若存在，格式包含 reg_result 或 org_result 的 successful_ids 数组。

"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


DEFAULT_CHECK_INTERVAL = 60
DEFAULT_STALL_MINUTES = 10
DEFAULT_RESULTS_ROOT = Path(__file__).resolve().parent / "results"
DEFAULT_MAX_DURATION_HOURS: Optional[float] = None
STATUS_FILE = Path(__file__).resolve().parent / "status.json"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
FUZZ_EXEC_ROOT = PROJECT_ROOT / "fuzz_exec"


def _now_ts() -> str:
	return time.strftime("%Y-%m-%d %H:%M:%S")


def _now_iso() -> str:
	return time.strftime("%Y-%m-%dT%H:%M:%S")


def _log(msg: str, log_path: Path) -> None:
	line = f"[{_now_ts()}] {msg}"
	print(line, flush=True)
	log_path.parent.mkdir(parents=True, exist_ok=True)
	with log_path.open("a", encoding="utf-8") as f:
		f.write(line + "\n")


def _count_files(dir_path: Path) -> int:
	if not dir_path.exists():
		return 0
	try:
		return sum(1 for p in dir_path.iterdir() if p.is_file())
	except Exception:
		return 0


def _ensure_root() -> None:
	if os.geteuid() != 0:
		print("Error: 请使用 sudo 启动该脚本（需要 root 权限）。", file=sys.stderr)
		sys.exit(2)


@dataclass
class FuzzStats:
	total_execs: Optional[int] = None
	unique_samples: Optional[int] = None
	unique_discarded: Optional[int] = None
	crashes: Optional[int] = None
	unique_crashes: Optional[int] = None
	hangs: Optional[int] = None
	offsets: Optional[int] = None
	execs_per_sec: Optional[int] = None

	def is_complete(self) -> bool:
		return (
			self.total_execs is not None
			and self.unique_samples is not None
			and self.crashes is not None
			and self.hangs is not None
			and self.offsets is not None
			and self.execs_per_sec is not None
		)


def _parse_fuzz_log(log_path: Path, max_lines: int = 800) -> Optional[FuzzStats]:
	if not log_path.exists():
		return None

	try:
		with log_path.open("r", encoding="utf-8", errors="ignore") as f:
			lines = f.readlines()
	except Exception:
		return None

	if not lines:
		return None

	# only inspect the tail to avoid huge logs
	lines = lines[-max_lines:]

	stats = FuzzStats()
	current = FuzzStats()

	def flush_current() -> None:
		nonlocal stats, current
		if current.is_complete():
			stats = current
			current = FuzzStats()

	for raw in lines:
		line = raw.strip()
		if not line:
			continue
		if line.startswith("Total execs:"):
			try:
				current.total_execs = int(line.split(":", 1)[1].strip())
			except Exception:
				pass
			flush_current()
			continue
		if line.startswith("Unique samples:"):
			try:
				right = line.split(":", 1)[1].strip()
				parts = right.split("(")
				current.unique_samples = int(parts[0].strip())
				if len(parts) > 1 and "discarded" in parts[1]:
					current.unique_discarded = int(parts[1].split()[0])
			except Exception:
				pass
			flush_current()
			continue
		if line.startswith("Crashes:"):
			try:
				right = line.split(":", 1)[1].strip()
				parts = right.split("(")
				current.crashes = int(parts[0].strip())
				if len(parts) > 1 and "unique" in parts[1]:
					current.unique_crashes = int(parts[1].split()[0])
			except Exception:
				pass
			flush_current()
			continue
		if line.startswith("Hangs:"):
			try:
				current.hangs = int(line.split(":", 1)[1].strip())
			except Exception:
				pass
			flush_current()
			continue
		if line.startswith("Offsets:"):
			try:
				current.offsets = int(line.split(":", 1)[1].strip())
			except Exception:
				pass
			flush_current()
			continue
		if line.startswith("Execs/s:"):
			try:
				current.execs_per_sec = int(float(line.split(":", 1)[1].strip()))
			except Exception:
				pass
			flush_current()
			continue

	# last chance
	if current.is_complete():
		stats = current

	return stats if stats.is_complete() else None


def _extract_fuzz_command(service_dir: Path) -> List[str]:
	run_sh = service_dir / "run.sh"
	if not run_sh.exists():
		raise FileNotFoundError(f"Missing run.sh in {service_dir}")

	cmd_line = ""
	with run_sh.open("r", encoding="utf-8", errors="ignore") as f:
		for line in f:
			if "coreaudiofuzzer" in line:
				cmd_line = line.strip()
				break

	if not cmd_line:
		raise ValueError("No fuzz command found in run.sh")

	if "sudo -E script -q /dev/null" in cmd_line:
		cmd_line = cmd_line.split("sudo -E script -q /dev/null", 1)[1].strip()
	if ">>" in cmd_line:
		cmd_line = cmd_line.split(">>", 1)[0].strip()

	return shlex.split(cmd_line)


def _build_isolated_run_sh(
	service_dir: Path,
	results_dir: Path,
	out_dir: Path,
	log_file: Path,
) -> Tuple[Path, Dict[str, str]]:
	cmd_tokens = _extract_fuzz_command(service_dir)
	if not cmd_tokens:
		raise ValueError("Empty fuzz command")

	# resolve coreaudiofuzzer path to absolute
	if not Path(cmd_tokens[0]).is_absolute():
		cmd_tokens[0] = str((service_dir / cmd_tokens[0]).resolve())

	instrument_module = ""
	dyld = ""
	harness = ""

	for i, tok in enumerate(cmd_tokens):
		if tok == "-instrument_module" and i + 1 < len(cmd_tokens):
			instrument_module = cmd_tokens[i + 1]
		if tok == "-target_env" and i + 1 < len(cmd_tokens):
			val = cmd_tokens[i + 1]
			if val.startswith("DYLD_INSERT_LIBRARIES="):
				dyld = val.split("=", 1)[1]

	if "--" in cmd_tokens:
		idx = cmd_tokens.index("--")
		if idx + 1 < len(cmd_tokens):
			harness = cmd_tokens[idx + 1]

	if not instrument_module or not dyld or not harness:
		raise ValueError("Failed to parse instrument_module/DYLD/harness from run.sh")

	resolved = {
		"instrument_module": instrument_module,
		"dyld": str((service_dir / dyld).resolve()),
		"harness": str((service_dir / harness).resolve()),
	}

	# rewrite tokens: -in/-out/-target_env and harness path
	new_tokens: List[str] = []
	idx = 0
	while idx < len(cmd_tokens):
		tok = cmd_tokens[idx]
		if tok == "-in" and idx + 1 < len(cmd_tokens):
			in_arg = cmd_tokens[idx + 1]
			if in_arg != "-":
				in_arg = str((service_dir / in_arg).resolve())
			new_tokens.extend([tok, in_arg])
			idx += 2
			continue
		if tok == "-out" and idx + 1 < len(cmd_tokens):
			new_tokens.extend([tok, str(out_dir)])
			idx += 2
			continue
		if tok == "-target_env" and idx + 1 < len(cmd_tokens):
			val = cmd_tokens[idx + 1]
			if val.startswith("DYLD_INSERT_LIBRARIES="):
				val = f"DYLD_INSERT_LIBRARIES={resolved['dyld']}"
			new_tokens.extend([tok, val])
			idx += 2
			continue
		if tok == "-nthreads" and idx + 1 < len(cmd_tokens):
			new_tokens.extend([tok, "1"])
			idx += 2
			continue
		if tok == "--" and idx + 1 < len(cmd_tokens):
			new_tokens.append(tok)
			new_tokens.append(resolved["harness"])
			idx += 2
			continue
		new_tokens.append(tok)
		idx += 1

	results_dir.mkdir(parents=True, exist_ok=True)
	out_dir.mkdir(parents=True, exist_ok=True)

	# copy service.json for harness startup
	service_json_src = service_dir / "service.json"
	service_json_dst = results_dir / "service.json"
	if service_json_src.exists():
		shutil.copy2(service_json_src, service_json_dst)
	else:
		raise FileNotFoundError(f"Missing service.json in {service_dir}")

	# copy optional check_result.json (valid message IDs)
	check_result_src = service_dir / "check_result.json"
	check_result_dst = results_dir / "check_result.json"
	if check_result_src.exists():
		shutil.copy2(check_result_src, check_result_dst)

	# copy initial corpus
	corpus_src = service_dir / "corpus"
	corpus_dst = results_dir / "corpus"
	if corpus_src.exists():
		shutil.copytree(corpus_src, corpus_dst, dirs_exist_ok=True)

	cmd = " ".join(shlex.quote(t) for t in new_tokens)
	cmd_with_log = f"sudo -E script -q /dev/null {cmd} >> {shlex.quote(str(log_file))} 2>&1"

	run_sh_path = results_dir / "run.sh"
	script_content = f"""#!/bin/bash
# Auto-generated isolated fuzzing script for {service_dir.name}

cd \"{results_dir}\" || exit

echo \"Starting fuzzing for {service_dir.name}, logging to {log_file.name}...\"
{cmd_with_log}
"""

	with run_sh_path.open("w", encoding="utf-8") as f:
		f.write(script_content)
	os.chmod(run_sh_path, 0o755)

	return run_sh_path, resolved


def _start_fuzzer(run_sh: Path, cwd: Path, log_path: Path) -> subprocess.Popen:
	_log(f"Starting fuzzer: {run_sh}", log_path)
	return subprocess.Popen(
		["sudo", "-E", str(run_sh)],
		cwd=str(cwd),
		preexec_fn=os.setsid,
	)


def _stop_process_group(proc: subprocess.Popen, log_path: Path) -> None:
	try:
		pgid = os.getpgid(proc.pid)
		os.killpg(pgid, signal.SIGTERM)
		_log(f"Sent SIGTERM to process group {pgid}", log_path)
	except Exception as e:
		_log(f"Failed to terminate process group: {e}", log_path)


def _load_status(status_path: Path) -> Dict:
	if status_path.exists():
		with status_path.open("r", encoding="utf-8") as f:
			return json.load(f)
	return {
		"config": {},
		"to_fuzz": [],
		"fuzzing": [],
		"fuzzed": [],
		"jobs": {},
	}


def _save_status(status_path: Path, data: Dict) -> None:
	status_path.parent.mkdir(parents=True, exist_ok=True)
	with status_path.open("w", encoding="utf-8") as f:
		json.dump(data, f, ensure_ascii=False, indent=2)


def _ensure_status_shape(data: Dict) -> Dict:
	data.setdefault("config", {})
	data.setdefault("to_fuzz", [])
	data.setdefault("fuzzing", [])
	data.setdefault("fuzzed", [])
	data.setdefault("jobs", {})
	return data


def _update_job(status_path: Path, data: Dict, service_name: str, fields: Dict) -> None:
	data = _ensure_status_shape(data)
	data["jobs"].setdefault(service_name, {})
	data["jobs"][service_name].update(fields)
	_save_status(status_path, data)


def _watch_fuzz(
	service_dir: Path,
	results_root: Path,
	status_path: Path,
	check_interval: int,
	stall_minutes: int,
	max_duration_hours: Optional[float],
) -> None:
	service_name = service_dir.name
	date_tag = time.strftime("%Y-%m-%d")
	results_dir = results_root / date_tag / service_name
	out_dir = results_dir / "out"
	log_path = results_dir / "fuzz_manager.log"
	log_file = results_dir / "fuzz.log"
	coverage_file = results_dir / "coverage_history.jsonl"

	_log(f"--- Starting fuzzing for {service_name} ---", log_path)

	try:
		run_sh, resolved = _build_isolated_run_sh(service_dir, results_dir, out_dir, log_file)
		_log(
			f"Parsed from run.sh: instrument_module={resolved['instrument_module']} dyld={resolved['dyld']} harness={resolved['harness']}",
			log_path,
		)
		proc = _start_fuzzer(run_sh, results_dir, log_path)
	except Exception as e:
		_log(f"Failed to start fuzzer: {e}", log_path)
		return

	last_count = _count_files(out_dir)
	initial_count = last_count
	stalled_seconds = 0
	start_time_ts = time.time()
	last_update_ts = _now_iso()
	last_offsets: Optional[int] = None

	status_data = _ensure_status_shape(_load_status(status_path))
	if service_name in status_data["to_fuzz"]:
		status_data["to_fuzz"].remove(service_name)
	if service_name not in status_data["fuzzing"]:
		status_data["fuzzing"].append(service_name)
	_update_job(
		status_path,
		status_data,
		service_name,
		{
			"status": "running",
			"start_time": _now_iso(),
			"paths": {
				"workspace": str(service_dir),
				"out_dir": str(out_dir),
				"log_file": str(log_file),
				"run_sh": str(results_dir / "run.sh"),
			},
			"history_file": str(coverage_file),
			"metrics": {
				"corpus_initial": initial_count,
				"corpus_current": last_count,
			},
		},
	)

	stop_reason = "stalled_10min"
	max_duration_seconds = None
	if max_duration_hours is not None:
		try:
			max_duration_seconds = max(0, int(float(max_duration_hours) * 3600))
		except Exception:
			max_duration_seconds = None
	try:
		while True:
			time.sleep(check_interval)

			if proc.poll() is not None:
				_log("Fuzzer process exited unexpectedly.", log_path)
				stop_reason = "process_exit"
				break

			elapsed_seconds = int(time.time() - start_time_ts)
			elapsed_min = int(elapsed_seconds / 60)
			if max_duration_seconds is not None and elapsed_seconds >= max_duration_seconds:
				_log(
					f"Reached max duration {max_duration_hours}h. Stopping fuzzing.",
					log_path,
				)
				stop_reason = "max_duration_reached"
				break

			current_count = _count_files(out_dir)
			stats = _parse_fuzz_log(log_file)

			if stats and stats.offsets is not None:
				offsets = stats.offsets
				changed = last_offsets is None or offsets > last_offsets
				if changed:
					_log(
						f"[Time: {elapsed_min}m] Offsets growth detected: {last_offsets} -> {offsets}",
						log_path,
					)
					last_offsets = offsets
					stalled_seconds = 0
					last_update_ts = _now_iso()

					entry = {
						"timestamp": _now_iso(),
						"offsets": offsets,
						"unique_samples": stats.unique_samples,
						"unique_discarded": stats.unique_discarded,
						"total_execs": stats.total_execs,
						"execs_per_sec": stats.execs_per_sec,
						"crashes": stats.crashes,
						"unique_crashes": stats.unique_crashes,
						"hangs": stats.hangs,
						"corpus_count": current_count,
					}
					coverage_file.parent.mkdir(parents=True, exist_ok=True)
					with coverage_file.open("a", encoding="utf-8") as f:
						f.write(json.dumps(entry, ensure_ascii=False) + "\n")
				else:
					stalled_seconds += check_interval
					stalled_min = int(stalled_seconds / 60)
					_log(
						f"[Time: {elapsed_min}m] Stalled for {stalled_min} min. (Offsets: {offsets})",
						log_path,
					)
			else:
				stalled_seconds += check_interval
				stalled_min = int(stalled_seconds / 60)
				_log(
					f"[Time: {elapsed_min}m] Stalled for {stalled_min} min. (No stats yet)",
					log_path,
				)

			if stalled_seconds >= stall_minutes * 60:
				_log(
					f"No new paths for {stall_minutes} minutes. Stopping fuzzing.",
					log_path,
				)
				break

			status_data = _ensure_status_shape(_load_status(status_path))
			job = status_data.get("jobs", {}).get(service_name, {})
			job_start_time = job.get("start_time")
			metrics = job.get("metrics", {})
			metrics.update(
				{
					"corpus_current": current_count,
				}
			)
			if stats:
				metrics.update(
					{
						"offsets_latest": stats.offsets,
						"unique_samples_latest": stats.unique_samples,
						"total_execs_latest": stats.total_execs,
						"execs_per_sec_latest": stats.execs_per_sec,
						"crashes_latest": stats.crashes,
						"hangs_latest": stats.hangs,
					}
				)
			_update_job(
				status_path,
				status_data,
				service_name,
				{
					"status": "running",
					"start_time": job_start_time,
					"paths": job.get("paths"),
					"history_file": job.get("history_file"),
					"metrics": metrics,
				},
			)
	except KeyboardInterrupt:
		_log("Experiment interrupted by user.", log_path)
		stop_reason = "interrupted"

	_stop_process_group(proc, log_path)
	_log(f"Fuzzing stopped. Final corpus size: {last_count}", log_path)

	end_time = _now_iso()
	duration_min = int((time.time() - start_time_ts) / 60)
	final_count = _count_files(out_dir)
	crashes_dir = out_dir / "crashes"
	crash_count = _count_files(crashes_dir)
	duration = time.strftime("%H:%M:%S", time.gmtime(time.time() - start_time_ts))

	status_data = _ensure_status_shape(_load_status(status_path))
	if service_name in status_data["fuzzing"]:
		status_data["fuzzing"].remove(service_name)
	if service_name not in status_data["fuzzed"]:
		status_data["fuzzed"].append(service_name)

	job = status_data.get("jobs", {}).get(service_name, {})
	metrics = job.get("metrics", {})
	metrics.update(
		{
			"corpus_final": final_count,
			"corpus_growth": max(0, final_count - initial_count),
		}
	)

	_update_job(
		status_path,
		status_data,
		service_name,
		{
			"status": "completed" if stop_reason == "stalled_10min" else "stopped_early",
			"start_time": job.get("start_time"),
			"end_time": end_time,
			"duration": duration,
			"stop_reason": stop_reason,
			"paths": job.get("paths"),
			"history_file": job.get("history_file"),
			"metrics": metrics,
		},
	)

	_log(f"--- Finished {service_dir.name} ---\n", log_path)


def _resolve_service_dir(item: str) -> Path:
	path = Path(item).expanduser()
	if path.exists():
		return path.resolve()
	return (FUZZ_EXEC_ROOT / item).resolve()


def main() -> int:
	_ensure_root()

	status_path = STATUS_FILE
	status_data = _ensure_status_shape(_load_status(status_path))
	config = status_data.get("config", {})

	check_interval = int(config.get("check_interval", DEFAULT_CHECK_INTERVAL))
	stall_minutes = int(config.get("stall_minutes", DEFAULT_STALL_MINUTES))
	max_duration_hours = config.get("max_duration_hours", DEFAULT_MAX_DURATION_HOURS)
	results_root = Path(config.get("results_root", DEFAULT_RESULTS_ROOT)).expanduser()
	if not results_root.is_absolute():
		results_root = PROJECT_ROOT / results_root
	results_root = results_root.resolve()
	max_duration_hours = config.get("max_duration_hours", DEFAULT_MAX_DURATION_HOURS)


	to_fuzz = status_data.get("to_fuzz", [])
	if not to_fuzz:
		print("status.json has empty to_fuzz list.", file=sys.stderr)
		return 1

	service_dirs = [_resolve_service_dir(item) for item in to_fuzz]
	service_dirs = [d for d in service_dirs if d.exists() and d.is_dir()]
	if not service_dirs:
		print("No valid service directories resolved from to_fuzz.", file=sys.stderr)
		return 1

	_save_status(status_path, status_data)

	for service_dir in service_dirs:
		_watch_fuzz(
			service_dir=service_dir,
			results_root=results_root,
			status_path=status_path,
			check_interval=check_interval,
			stall_minutes=stall_minutes,
			max_duration_hours=max_duration_hours,
		)

	return 0


if __name__ == "__main__":
	raise SystemExit(main())
# Frozen 1.x compatibility ownership for PR-07.
from __future__ import annotations

from dataclasses import dataclass


_LEGACY_GLOBAL_NAMES = ("__file__", "os", "sys", "hashlib", "normalize_controller_config", "CONFIG_PATH", "json", "threading", "_process_image_path", "_rcm_process_pids_checked", "time", "CREATE_NO_WINDOW", "_IS_WIN", "subprocess", "socket", "DEFAULT_OFFICIAL_EXE_PATH", "re", "config_dir", "resource_path", "_release_single_instance", "shutil", "DEFAULT_CLUSTER_MANIFEST_PATH", "validate_cluster_manifest", "write_cluster_manifest", "TROUBLE_LOG_PATH", "_append_log_record", "resolve_identity", "is_controller_config", "tk", "_dashboard_ip_alive", "requests", "is_controller_node", "messagebox", "OperationProgressDialog")


def bind_legacy_globals(namespace):
    globals().update({name: namespace[name] for name in _LEGACY_GLOBAL_NAMES})
    globals()["OperationProgressDialog"] = lambda *args, **kwargs: namespace["OperationProgressDialog"](*args, **kwargs)
    globals()["file_sha256"] = lambda *args, **kwargs: namespace["file_sha256"](*args, **kwargs)
    globals()["save_config"] = lambda *args, **kwargs: _save_config_with_namespace(namespace, *args, **kwargs)
    namespace["save_config"] = globals()["save_config"]


def current_binary_path() -> str:
    return sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)


def file_sha256(path: str, limit_bytes: Optional[int] = None) -> str:
    try:
        h = hashlib.sha256()
        read_total = 0
        with open(path, "rb") as f:
            while True:
                if limit_bytes is None:
                    chunk = f.read(1024 * 1024)
                else:
                    remain = max(0, int(limit_bytes) - read_total)
                    if remain <= 0:
                        break
                    chunk = f.read(min(1024 * 1024, remain))
                if not chunk:
                    break
                h.update(chunk)
                read_total += len(chunk)
        return h.hexdigest().upper()
    except Exception as exc:
        return f"<sha unavailable: {type(exc).__name__}>"


def save_config(cfg: dict, raise_on_error: bool = False) -> bool:
    tmp_path = None
    try:
        data = normalize_controller_config(cfg)
        persist_temp_port = data.pop("_persist_temp_port", None)
        for key in list(data.keys()):
            if key.startswith("_runtime_") or key.startswith("_persist_"):
                data.pop(key, None)
        if (os.environ.get("RCM_SKIP_UAC_FOR_TESTS") == "1"
                and os.environ.get("RCM_TEST_TEMP_PORT")
                and persist_temp_port is not None):
            data["temp_port"] = persist_temp_port
        tmp_path = (CONFIG_PATH + f".tmp.{os.getpid()}."
                    f"{threading.get_ident()}")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, CONFIG_PATH)
        return True
    except Exception as exc:
        print("config write error:", exc)
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        if raise_on_error:
            raise
        return False


def _norm_file_path(path: str) -> str:
    try:
        return os.path.normcase(os.path.abspath(path or ""))
    except Exception:
        return os.path.normcase(path or "")


def _is_real_sha(value: str) -> bool:
    return bool(value) and not str(value).startswith("<sha unavailable")


def _replacement_targets_from_processes() -> tuple[
        Optional[list[int]], list[int], list[tuple[int, str]], str]:
    pids, err = _rcm_process_pids_checked()
    if pids is None:
        return None, [], [], f"could not list RCM processes: {err}"
    current = os.getpid()
    current_path = _norm_file_path(current_binary_path())
    current_sha = file_sha256(current_binary_path())
    have_current_sha = _is_real_sha(current_sha)
    stale: list[int] = []
    same: list[int] = []
    unknown: list[tuple[int, str]] = []
    notes: list[str] = []
    for pid in sorted(set(pids)):
        if pid == current:
            continue
        path, perr = _process_image_path(pid)
        if not path:
            unknown.append((pid, perr))
            notes.append(f"pid {pid}: path unavailable ({perr})")
            continue
        proc_sha = file_sha256(path)
        same_path = _norm_file_path(path) == current_path
        same_sha = have_current_sha and proc_sha == current_sha
        if same_path or same_sha:
            same.append(pid)
            notes.append(f"pid {pid}: current build ({path})")
        else:
            stale.append(pid)
            short = proc_sha[:12] if _is_real_sha(proc_sha) else proc_sha
            notes.append(f"pid {pid}: different binary sha={short} ({path})")
    return stale, same, unknown, "; ".join(notes) or "no other RCM process"


def needs_rcm_control_server(cfg: dict, controller_only: bool) -> bool:
    """Keep the read-only loopback server only for local metrics/temperature."""
    if controller_only:
        return False
    return bool(
        cfg.get("temp_enabled", True)
        or cfg.get("metrics_enabled", True))


@dataclass
class ActionResult:
    ok: bool
    message: str


class LegacyRayAppMixin:
    def _set_repair_status(self, state: str, message: str = "", ok: bool = True):
        self._repair_status = {
            "ok": bool(ok),
            "state": str(state or ""),
            "message": str(message or ""),
            "ts": time.time(),
        }


    def _repair_status_snapshot(self) -> dict:
        data = dict(getattr(self, "_repair_status", {}) or {})
        data.setdefault("ok", True)
        data.setdefault("state", "idle")
        data.setdefault("message", "")
        data.setdefault("ts", 0.0)
        data.setdefault("role", getattr(self, "role", ""))
        data.setdefault("local_ip", getattr(self, "ip", ""))
        return data


    def _ray_firewall_ready(self) -> Optional[bool]:
        if not _IS_WIN:
            return None
        now = time.time()
        if (self._firewall_ready_cache is not None
                and now - self._firewall_ready_ts < 60.0):
            return bool(self._firewall_ready_cache)
        ready = False
        try:
            command = (
                "$r=Get-NetFirewallRule -Name 'Ray-Tailscale-In' "
                "-ErrorAction SilentlyContinue; "
                "if($r -and $r.Enabled -eq 'True'){'ready'}")
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True, text=True, timeout=6,
                creationflags=CREATE_NO_WINDOW)
            ready = (proc.stdout or "").strip() == "ready"
        except Exception:
            ready = False
        self._firewall_ready_cache = ready
        self._firewall_ready_ts = now
        return ready


    def _health_snapshot(self) -> dict:
        return {
            "host": socket.gethostname(),
            "role": ("controller" if getattr(self, "controller_only", False)
                     else getattr(self, "role", "")),
            "local_ip": getattr(self, "ip", ""),
            "cpus": getattr(self, "cpus", 0),
            "head_ip": self.cfg.get("head_ip"),
            "temp_port": self.cfg.get("temp_port"),
            "cluster_epoch": self.cfg.get("cluster_epoch", 0),
            "ray_firewall_ready": self._ray_firewall_ready(),
        }


    def _handle_self_update(self, expect_sha256: str, source: str) -> dict:
        del expect_sha256, source
        return {
            "_status": 410,
            "ok": False,
            "accepted": False,
            "reason": "legacy_remote_retired",
        }
        """Validate the shared official EXE before accepting async replacement."""
        expected = str(expect_sha256 or "").strip().upper()
        if source != "official":
            return {
                "_status": 400, "ok": False, "accepted": False,
                "reason": "invalid_source",
            }
        official = os.path.normpath(
            str(self.cfg.get("official_exe_path")
                or DEFAULT_OFFICIAL_EXE_PATH))
        if not os.path.isfile(official):
            return {
                "_status": 503, "ok": False, "accepted": False,
                "reason": "official_missing",
            }
        actual = file_sha256(official)
        if actual != expected:
            return {
                "_status": 422, "ok": False, "accepted": False,
                "reason": "sha_mismatch", "actual": actual,
            }
        current = str(
            getattr(self, "_startup_binary_sha", "") or "").strip().upper()
        if not re.fullmatch(r"[A-F0-9]{64}", current):
            # Compatibility fallback for synthetic/tests that bypass
            # RayApp.__init__. Production instances always capture startup
            # identity before the metrics server becomes reachable.
            current = file_sha256(current_binary_path())
        if current == expected:
            return {
                "_status": 409, "ok": False, "accepted": False,
                "reason": "already_current", "current_sha": current,
                "target_sha": expected,
            }
        with self._self_update_lock:
            if self._self_update_pending:
                return {
                    "_status": 409, "ok": False, "accepted": False,
                    "reason": "update_pending", "current_sha": current,
                    "target_sha": expected,
                }
            self._self_update_pending = True
        threading.Thread(
            target=self._perform_self_update,
            args=(official, expected),
            daemon=True,
            name="SelfUpdatePrepare").start()
        return {
            "_status": 202, "ok": True, "accepted": True,
            "current_sha": current, "target_sha": expected,
        }


    def _launch_self_update_helper(
            self, current: str, staged: str, expected: str) -> None:
        del self, current, staged, expected
        return
        helper = resource_path("self_update_helper.ps1")
        if not os.path.isfile(helper):
            raise FileNotFoundError(f"self-update helper missing: {helper}")
        log_path = os.path.join(config_dir(), "self_update.log")
        subprocess.Popen(
            [
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", helper,
                "-RcmProcessId", str(os.getpid()),
                "-CurrentPath", current,
                "-NewPath", staged,
                "-ExpectedSha256", expected,
                "-LogPath", log_path,
            ],
            creationflags=CREATE_NO_WINDOW,
            close_fds=True,
        )


    def _perform_self_update(self, official: str, expected: str) -> None:
        del official, expected
        return
        """Stage, re-verify, launch the helper, then quit RCM without Ray."""
        current = os.path.normpath(current_binary_path())
        staged = current + ".new"
        try:
            shutil.copy2(official, staged)
            copied_sha = file_sha256(staged)
            if copied_sha != expected:
                raise ValueError(
                    f"staged SHA mismatch: expected {expected}, "
                    f"got {copied_sha}")
            self._log(
                "self-update: staged verified official EXE; "
                "Ray will remain running")
            self._launch_self_update_helper(
                current, staged, expected)
            # The replacement helper waits for this PID.  Release the named
            # mutex before initiating the no-Ray-stop quit path so the new
            # instance can acquire it immediately after replacement.
            _release_single_instance()
            self._post(
                lambda: self._quit(
                    False, source="self-update (preserve Ray)"))
        except Exception as exc:
            with self._self_update_lock:
                self._self_update_pending = False
            self._log(
                "self-update failed before quit: "
                f"{type(exc).__name__}: {exc}")
            self._record_guard_trouble(
                "RCM_DIAG_EVENT self-update preparation failed: "
                f"{type(exc).__name__}: {exc}")


    def _handle_cluster_config(self, payload: dict) -> dict:
        del payload
        return {
            "_status": 410,
            "ok": False,
            "accepted": False,
            "reason": "legacy_remote_retired",
        }
        """Persist a newer epoch, acknowledge it, then converge asynchronously."""
        manifest = validate_cluster_manifest(payload)
        with self._cluster_config_lock:
            try:
                current_epoch = int(self.cfg.get("cluster_epoch") or 0)
            except (TypeError, ValueError):
                current_epoch = 0
            if manifest["epoch"] <= current_epoch:
                return {
                    "_status": 409,
                    "ok": False,
                    "accepted": False,
                    "reason": "stale_epoch",
                    "current_epoch": current_epoch,
                }
            new_cfg = json.loads(json.dumps(self.cfg))
            new_cfg["head_ip"] = manifest["head_ip"]
            new_cfg["nodes"] = manifest["nodes"]
            new_cfg["cluster_epoch"] = manifest["epoch"]
            local_ip = str(getattr(self, "ip", "") or "").strip()
            for node in manifest["nodes"]:
                if str(node.get("ip") or "").strip() != local_ip:
                    continue
                new_cfg.setdefault("this", {})
                new_cfg["this"]["role"] = node["role"]
                new_cfg["this"]["num_cpus"] = node["num_cpus"]
                break
            save_config(new_cfg, raise_on_error=True)
            write_cluster_manifest(
                str(new_cfg.get("cluster_manifest_path")
                    or DEFAULT_CLUSTER_MANIFEST_PATH),
                manifest)
            # Publish the accepted epoch in-process before returning 202 so a
            # concurrent duplicate/stale request cannot pass the same guard.
            self.cfg = new_cfg
            self.controller.cfg = new_cfg
            self.controller.repairing = True
            self._schedule_cluster_convergence(new_cfg, manifest)
        self._record_cluster_event(
            f"accepted epoch={manifest['epoch']} "
            f"head={manifest['head_ip']}; local convergence scheduled")
        return {
            "_status": 202,
            "ok": True,
            "accepted": True,
            "epoch": manifest["epoch"],
        }


    def _record_cluster_event(self, message: str):
        line = (
            time.strftime("%Y-%m-%d %H:%M:%S ")
            + f"[WARN] RCM_CLUSTER_EVENT {message}\n")
        try:
            self._log("RCM_CLUSTER_EVENT " + message)
            _append_log_record(TROUBLE_LOG_PATH, line)
        except Exception:
            pass


    def _schedule_cluster_convergence(
            self, new_cfg: dict, manifest: dict) -> None:
        del new_cfg, manifest
        return
        timer = threading.Timer(
            0.5, self._converge_to_cluster_config,
            args=(new_cfg, manifest))
        timer.daemon = True
        timer.name = "ClusterConfigConverge"
        timer.start()


    def _converge_to_cluster_config(
            self, new_cfg: dict, manifest: dict) -> None:
        del new_cfg, manifest
        return
        """Stop local Ray, then start/join under the newly accepted epoch."""
        controller = self.controller
        try:
            controller.cfg = new_cfg
            role, _, _ = resolve_identity(new_cfg)
            self._record_cluster_event(
                f"epoch={manifest['epoch']} local stop before role={role}")
            stopped = controller.stop()
            if not stopped.ok:
                self._record_cluster_event(
                    f"epoch={manifest['epoch']} stop warning: "
                    f"{stopped.message}")
            if controller._shutdown_requested():
                return
            if role == "head":
                result = controller.start_head()
            else:
                deadline = time.monotonic() + 75.0
                while time.monotonic() < deadline:
                    if controller._shutdown_requested():
                        return
                    if controller.head_alive(timeout=2.0):
                        break
                    time.sleep(2.0)
                result = controller.start_worker()
            self._record_cluster_event(
                f"epoch={manifest['epoch']} role={role} "
                f"result={'ok' if result.ok else 'failed'} "
                f"{result.message}")
        except Exception as exc:
            self._record_cluster_event(
                f"epoch={manifest.get('epoch')} convergence error "
                f"{type(exc).__name__}: {exc}")
        finally:
            controller.repairing = False
            self._post(
                lambda: self._apply_cluster_config_runtime(new_cfg))


    def _apply_cluster_config_runtime(self, cfg: dict):
        del cfg
        return
        if self._closing:
            return
        self.cfg = cfg
        self.role, self.ip, self.cpus = resolve_identity(cfg)
        self.controller.cfg = cfg
        self.controller_only = is_controller_config(cfg, self.ip)
        identity_role = "CONTROLLER" if self.controller_only else self.role.upper()
        try:
            self.id_lbl.configure(
                text=f"{identity_role} on {self.ip or 'no-ip'}   "
                f"({self.cpus} CPU)")
            self.btn_start.configure(
                text=("Start" if self.role == "head" else "Join"))
        except tk.TclError:
            pass
        self._sync_watchdog_runtime()
        self._start_monitor()


    def _repair_local_ray(self) -> ActionResult:
        self.controller.repairing = True
        self._set_repair_status("running", "local repair running", ok=True)
        try:
            self.controller.auto_paused = False
            self._auto_pause_fired = False
            self._cool_streak = 0
            if self.role == "head":
                if self.controller.head_alive(timeout=2.5):
                    return ActionResult(True, "Head Ray is already healthy.")
                self._log("repair: head dashboard missing - clean reset then Start")
                reset = self.controller.clean_reset()
                self._clear_monitor_metric_cache()
                if not reset.ok:
                    return reset
                time.sleep(2.0)
                return self.controller.start_head()

            alive, checked = _dashboard_ip_alive(self.cfg, self.ip, timeout=3.0)
            if checked and alive:
                return ActionResult(True, "Worker is already Ray ALIVE.")
            if not checked:
                return ActionResult(
                    False,
                    "Head dashboard API unavailable; not resetting worker.")
            self._log("repair: worker missing from Ray dashboard - clean reset then Join")
            reset = self.controller.clean_reset()
            self._clear_monitor_metric_cache()
            if not reset.ok:
                return reset
            time.sleep(2.0)
            return self.controller.start_worker()
        finally:
            self.controller.repairing = False


    def _request_remote_repair(self, node: dict, alive_ips: set[str], checked: bool) -> tuple[bool, str]:
        del node, alive_ips, checked
        return False, "legacy_remote_retired"
        name = str(node.get("name") or node.get("ip") or "node")
        ip = str(node.get("ip") or "").strip()
        port = int(self.cfg.get("temp_port", 8866))
        try:
            health = requests.get(f"http://{ip}:{port}/health", timeout=2.0)
            if not health.ok:
                return False, f"{name}: RCM health HTTP {health.status_code}"
        except Exception:
            return False, f"{name}: RCM offline"
        try:
            res = requests.post(
                f"http://{ip}:{port}/repair",
                headers={"X-RCM-Repair": "1"},
                data=b"",
                timeout=4.0)
            if res.status_code == 404:
                return False, f"{name}: restart/update RCM for Repair"
            try:
                payload = res.json()
            except Exception:
                payload = {}
            msg = str(payload.get("message") or "").strip()
            if res.ok and payload.get("accepted", True):
                return True, f"{name}: repair accepted"
            if res.status_code == 409 and "already running" in msg.lower():
                return True, f"{name}: repair already running"
            if res.ok:
                return False, f"{name}: {msg or 'repair not accepted'}"
            return False, f"{name}: repair HTTP {res.status_code}"
        except requests.Timeout:
            return False, f"{name}: repair request timed out"
        except Exception as exc:
            return False, f"{name}: repair {type(exc).__name__}"


    def _repair_cluster(self) -> ActionResult:
        local = self._repair_local_ray()
        self._clear_monitor_metric_cache()
        return local


    def _run_repair_flow(self) -> ActionResult:
        if not self._repair_lock.acquire(blocking=False):
            return ActionResult(False, "Repair is already running.")
        try:
            self._log("repair: self-diagnosis started")
            self._set_repair_status("running", "self diagnosis running", ok=True)
            res = self._repair_cluster()
            self._log(("repair: OK - " if res.ok else "repair: FAILED - ") + res.message)
            self._set_repair_status(
                "ok" if res.ok else "failed", res.message, ok=res.ok)
            return res
        finally:
            try:
                self._repair_lock.release()
            except RuntimeError:
                pass


    def _remote_repair_request(self) -> dict:
        return {
            "_status": 410,
            "ok": False,
            "accepted": False,
            "reason": "legacy_remote_retired",
        }


    def _do_repair(self):
        if self.controller_only:
            return
        if self._busy:
            return
        ok = messagebox.askyesno(
            "Repair",
            "Run self diagnosis and repair stuck Ray state?\n\n"
            "This repairs only the local Ray node. No remote RCM endpoint is used.")
        if not ok:
            return
        self.controller.auto_paused = False
        self._auto_pause_fired = False
        self._cool_streak = 0
        self._optimistic("repairing...")
        self._run_bg(self._run_repair_flow, "repairing...")


    def _do_fleet_update(self):
        messagebox.showinfo(
            "Update Fleet unavailable",
            "legacy_remote_retired",
            parent=self)
        return ActionResult(False, "legacy_remote_retired")
        if self._busy:
            return
        official = os.path.normpath(
            str(self.cfg.get("official_exe_path")
                or DEFAULT_OFFICIAL_EXE_PATH))
        if not os.path.isfile(official):
            messagebox.showerror(
                "Update Fleet",
                f"Official executable not found:\n{official}",
                parent=self)
            return
        target_sha = file_sha256(official)
        if not re.fullmatch(r"[A-F0-9]{64}", target_sha):
            messagebox.showerror(
                "Update Fleet",
                "Could not calculate the official executable SHA256.",
                parent=self)
            return
        progress = OperationProgressDialog(self, "Update Fleet")
        self._set_busy(True, "checking fleet...")
        progress.append(f"Official SHA256: {target_sha}")

        def note(text):
            self._post(lambda text=text: progress.append(text))

        def preflight():
            rows = []
            port = int(self.cfg.get("temp_port") or 8866)
            for node in self.cfg.get("nodes", []):
                if not isinstance(node, dict) or is_controller_node(node):
                    continue
                rec = dict(node)
                ip = str(rec.get("ip") or "").strip()
                rec["_health"] = None
                rec["_state"] = "unreachable"
                if ip:
                    try:
                        response = requests.get(
                            f"http://{ip}:{port}/health", timeout=4.0)
                        if response.ok:
                            health = response.json()
                            rec["_health"] = (
                                health if isinstance(health, dict) else {})
                            rec["_state"] = (
                                "current"
                                if str(rec["_health"].get("sha256") or "").upper()
                                == target_sha else "target")
                        else:
                            rec["_state"] = f"HTTP {response.status_code}"
                    except Exception:
                        pass
                rows.append(rec)
            self._post(lambda rows=rows: confirm(rows))

        def confirm(rows):
            if not progress.winfo_exists():
                self._set_busy(False)
                return
            current = [
                str(row.get("name") or row.get("ip"))
                for row in rows if row["_state"] == "current"]
            targets = [
                str(row.get("name") or row.get("ip"))
                for row in rows if row["_state"] == "target"]
            unreachable = [
                str(row.get("name") or row.get("ip"))
                for row in rows
                if row["_state"] not in ("current", "target")]
            for name in current:
                progress.append(f"{name}: already current")
            for name in unreachable:
                progress.append(f"{name}: unreachable")
            if not targets:
                self._set_busy(False)
                progress.finish(
                    f"No updates needed · current {len(current)} · "
                    f"unreachable {len(unreachable)}",
                    ok=not unreachable)
                return
            message = (
                "Update the following reachable nodes from the shared "
                "official executable?\n\n"
                + "\n".join(f"• {name}" for name in targets)
                + ("\n\nUnreachable (will be skipped):\n"
                   + "\n".join(f"• {name}" for name in unreachable)
                   if unreachable else "")
                + "\n\nRay will remain running. The head is updated last.")
            if not messagebox.askyesno(
                    "Update Fleet", message, parent=progress):
                self._set_busy(False)
                progress.finish("Cancelled", ok=False)
                return
            threading.Thread(
                target=execute, args=(rows,), daemon=True,
                name="FleetUpdate").start()

        def execute(rows):
            port = int(self.cfg.get("temp_port") or 8866)
            targets = [row for row in rows if row["_state"] == "target"]
            # A head update is always the final network request.
            targets.sort(
                key=lambda row: 1 if row.get("role") == "head" else 0)
            updated = 0
            failed = 0
            for row in targets:
                if progress.cancel_event.is_set():
                    break
                name = str(row.get("name") or row.get("ip"))
                ip = str(row.get("ip") or "").strip()
                health = row.get("_health") or {}
                if not health.get("self_update_v1"):
                    failed += 1
                    note(f"{name}: failed — old RCM lacks self_update_v1")
                    continue
                note(f"{name}: sending update request...")
                try:
                    response = requests.post(
                        f"http://{ip}:{port}/self-update",
                        headers={"X-RCM-Update": "v1"},
                        json={
                            "expect_sha256": target_sha,
                            "source": "official",
                        },
                        timeout=8.0)
                    payload = response.json() if response.content else {}
                    if response.status_code == 409 and (
                            payload.get("reason") == "already_current"):
                        note(f"{name}: already current")
                        continue
                    if response.status_code != 202:
                        failed += 1
                        note(
                            f"{name}: failed — HTTP {response.status_code} "
                            f"{payload.get('reason') or ''}".rstrip())
                        continue
                except Exception as exc:
                    failed += 1
                    note(f"{name}: request failed — {type(exc).__name__}")
                    continue
                deadline = time.monotonic() + 90.0
                verified = False
                while time.monotonic() < deadline:
                    if progress.cancel_event.wait(2.0):
                        break
                    try:
                        check = requests.get(
                            f"http://{ip}:{port}/health", timeout=4.0)
                        data = check.json() if check.ok else {}
                        if str(data.get("sha256") or "").upper() == target_sha:
                            verified = True
                            break
                    except Exception:
                        pass
                if verified:
                    updated += 1
                    note(f"{name}: updated and verified")
                elif not progress.cancel_event.is_set():
                    failed += 1
                    note(f"{name}: failed — new SHA not seen within 90s")
            cancelled = progress.cancel_event.is_set()
            summary = (
                f"{'Cancelled' if cancelled else 'Finished'} · "
                f"updated {updated} · failed {failed}")
            self._post(lambda: (
                self._set_busy(False),
                progress.finish(summary, ok=(failed == 0 and not cancelled))))

        threading.Thread(
            target=preflight, daemon=True,
            name="FleetUpdatePreflight").start()


_LEGACY_SAVE_CONFIG = save_config


def _save_config_with_namespace(namespace, *args, **kwargs):
    globals()["CONFIG_PATH"] = namespace["CONFIG_PATH"]
    return _LEGACY_SAVE_CONFIG(*args, **kwargs)

"""Argument-independent dispatch and terminal views for local workspaces."""

from . import product, workspace as ws, workspace_report, workspace_search


def execute(args):
    command = args.command
    if command in product.COMMANDS:
        return user_view(args)
    if command == "init":
        with ws.project(args.root) as (root, installed):
            with ws.open_registry(root, optional=True) as registry:
                if registry is not None:
                    return ws.payload(command, "ALREADY_INITIALIZED", ws.reviewable_registry(registry)), 0
            ws.reject_initialized_ancestor(root, installed)
            created = ws.create(root)
            with ws.open_registry(root) as registry:
                data = ws.reviewable_registry(registry)
        return ws.payload(command, "CREATED" if created else "ALREADY_INITIALIZED", data), 0
    if command == "report":
        return own_report(args)
    if command in ("search", "verify"):
        query = args.literal if command == "search" else None
        with ws.discover() as registry:
            if query is None:
                return workspace_search.observe(registry)
            return workspace_search.observe(registry, query=query, limit=args.limit,
                                            ignore_case=args.ignore_case, all_matches=args.all_matches)
    with ws.discover(write=not args.preview) as registry:
        if not args.preview and not ws.search.code_matches():
            raise ws.WorkspaceError("CODE_CHANGED", "Reinstalá la wheel antes de registrar fuentes.", 1)
        data = ws.Scan(registry, args.preview, args.refresh).run()
    return ws.payload(command, "PARTIAL" if data["partial"] else "COMPLETE", data), 3 if data["partial"] else 0


def own_report(args):
    if args.store is not None:
        raise ws.WorkspaceError("REPORT_STORE_CONFLICT", "Los informes del workspace se guardan bajo .pgopcore/reports.")
    action = args.report_action
    if action == "create":
        if args.package_id is not None or args.request_key is not None or args.query is None:
            raise ws.WorkspaceError("INVALID_REPORT_REQUEST", 'Usá pgop report create --query "texto exacto".')
        with ws.discover() as registry:
            return workspace_report.create(registry, args.query, limit=args.limit,
                                           ignore_case=args.ignore_case, all_matches=args.all_matches)
    if not workspace_report.ID.fullmatch(args.report_id):
        raise ws.WorkspaceError("INVALID_REPORT_ID", "Usá el ID exacto del informe, o --store si es histórico.")
    with ws.discover(load_journal=False) as registry:
        if action == "show":
            return workspace_report.read(registry, args.report_id, show=True)
        if args.artifact not in (None, "REPORT.json"):
            raise ws.WorkspaceError("INVALID_ARTIFACT", "Los informes del workspace usan REPORT.json.")
        return workspace_report.read(registry, args.report_id, show=False, offset=args.offset, limit=args.limit)


def user_view(args):
    command = args.command
    baseline, code = product.execute(args)
    if code or baseline["outcome"] == "USAGE_ERROR":
        return baseline, code
    remove = command == "catalog" and args.catalog_action == "remove"
    if remove and (not ws.SOURCE_ID.fullmatch(args.source_id) or args.offset != 0 or args.limit != 10):
        return product.usage_error(command, "INVALID_ARGUMENT")
    try:
        ws.io.api()
        with ws.discover(write=remove, optional=not remove) as registry:
            if registry is None:
                return baseline, code
            if remove:
                return remove_source(registry, args.source_id)
            view = ws.reviewable_registry(registry)
            if command == "catalog":
                rows = registry.value["rows"]
                end = args.offset + args.limit
                data = {**baseline["data"], **view, "registry": "CONFIGURED",
                        "items": rows[args.offset:end], "total": len(rows),
                        "next_offset": end if end < len(rows) else None}
                return product.response(command, "CONFIGURED", data), 0
            data = {**baseline["data"], **view, "workspace": "CONFIGURED", "user_catalog": "CONFIGURED"}
            return product.response(command, baseline["outcome"] if command == "doctor" else "CONFIGURED",
                                    data, baseline["native_code"]), 0
    except ws.WorkspaceError as exc:
        if exc.code == "ROOT_NOT_ALLOWED" and not remove:
            return baseline, code
        raise
    except ws.io.SafeIOError as exc:
        if not remove and exc.code.startswith(("UNSUPPORTED_WINDOWS", "UNSUPPORTED_SAFE_READ")):
            return baseline, code
        if not remove and exc.code == "OUTPUT_OVERLAPS_INPUT":
            baseline["native_code"] = "WORKSPACE_LOCATION_OVERLAPS_INSTALLATION"
            return baseline, code
        raise


def remove_source(registry, source_id):
    for row in registry.value["rows"]:
        if row["id"] == source_id:
            if row["status"] != "REMOVED":
                rows = [dict(item, status="REMOVED") if item["id"] == source_id else item
                        for item in registry.value["rows"]]
                registry.save(dict(registry.value, rows=rows))
            return ws.payload("catalog", "REMOVED", {"id": source_id, "path": row["path"],
                                                     "revision": registry.revision}), 0
    raise ws.WorkspaceError("UNKNOWN_SOURCE", "El ID no corresponde al registro. Consultá pgop catalog.")


def human_lines(result):
    command, outcome, data = result["command"], result["outcome"], result["data"]
    if command == "init":
        return [f'Espacio de trabajo listo en {data["root"]}.', "Para registrar fuentes, ejecutá pgop scan."]
    if outcome == "REMOVED":
        return [f'Fuente retirada: {data["id"]} · {data["path"]}.']
    if command == "scan":
        action = "Previsualización" if data["preview"] else "Registro"
        lines = [f'{action}: {len(data["candidates"])} candidatas · {data["examined_entries"]} entradas examinadas.',
                 f'{data["registered_sources"]} fuentes registradas · {data["captured_valid_bytes"]} bytes nuevos capturados.']
        lines.extend(f'  {item["path"]} · {item["bytes"]} bytes' for item in data["candidates"][:20])
        if len(data["candidates"]) > 20:
            lines.append("La salida JSON contiene la lista completa de candidatas.")
        if data["excluded"]:
            lines.append("Exclusiones: " + counts(data["excluded"]))
        if data["partial"]:
            lines.append("Cobertura parcial: " + counts(data["reasons"]))
        limits = data["limits"]
        lines.append(f'Topes: {limits["registered_rows"]} filas, {limits["corpus_bytes"] // (1024 * 1024)} MiB, '
                     f'{limits["directories_deep"]} niveles, {limits["entries"]} entradas.')
        lines.append("Para confirmar el registro, ejecutá pgop scan." if data["preview"]
                     else "Para consultar las fuentes, ejecutá pgop catalog.")
        return lines
    if command in ("search", "verify"):
        return workspace_search.human_lines(result)
    if command == "report":
        return workspace_report.human_lines(result)
    return product.human_lines(result)


def counts(mapping):
    return ", ".join(f"{name}={count}" for name, count in sorted(mapping.items()))

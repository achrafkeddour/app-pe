"""
Open5GS v2.7.7 + UERANSIM v3.2.6 — PFE 2026
AI Platform 5G — Backend

Architecture:
  open5gs_pfe_pure.log
        ↓  metrics_engine.compute_metrics()
  metrics_computed.json
        ↓  Prophet ML
  /api/data  /api/predictions  → dashboard
"""

import os, sys, json, warnings
import pandas as pd
from flask import Flask, jsonify, send_from_directory

warnings.filterwarnings("ignore")

# ── Prophet ───────────────────────────────────────────────────────────────────
try:
    from prophet import Prophet as _ProphetClass
    PROPHET_AVAILABLE = True
except ImportError:
    PROPHET_AVAILABLE = False
    print("⚠  Prophet not installed — run: pip install prophet")

# ── Metrics engine ────────────────────────────────────────────────────────────
try:
    from metrics_engine import compute_metrics, save_metrics, find_log
    METRICS_ENGINE_OK = True
except ImportError:
    METRICS_ENGINE_OK = False
    print("⚠  metrics_engine.py not found next to app.py")

app = Flask(__name__, static_folder="static", static_url_path="")
_cache = {}
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
METRICS_FILE = os.path.join(SCRIPT_DIR, "metrics_computed.json")


# ══════════════════════════════════════════════════════════════════════════════
#  PROPHET
# ══════════════════════════════════════════════════════════════════════════════
def run_prophet(df, periods=8, freq="15min"):
    if not PROPHET_AVAILABLE:
        return {"error": "Prophet not installed", "historical": [], "forecast": []}
    if len(df) < 5:
        return {"error": "Not enough data points", "historical": [], "forecast": []}
    df = df.copy()
    df["ds"] = pd.to_datetime(df["ds"])
    df = df.sort_values("ds").drop_duplicates("ds")
    m = _ProphetClass(
        yearly_seasonality=False, weekly_seasonality=False,
        daily_seasonality=True, changepoint_prior_scale=0.15,
        seasonality_prior_scale=5.0, interval_width=0.80,
    )
    m.fit(df)
    future   = m.make_future_dataframe(periods=periods, freq=freq)
    forecast = m.predict(future)
    hist  = forecast[forecast["ds"].isin(df["ds"])][["ds","yhat","yhat_lower","yhat_upper"]].copy()
    hist["actual"] = df.set_index("ds")["y"].reindex(hist["ds"]).values
    fcast = forecast[~forecast["ds"].isin(df["ds"])][["ds","yhat","yhat_lower","yhat_upper"]].copy()
    def fmt(r):
        return {"ds":r["ds"].strftime("%Y-%m-%dT%H:%M:%S"),
                "yhat":round(float(r["yhat"]),4),
                "yhat_lower":round(float(r["yhat_lower"]),4),
                "yhat_upper":round(float(r["yhat_upper"]),4)}
    def fmt_h(r):
        d=fmt(r); v=r.get("actual")
        d["actual"]=round(float(v),4) if v is not None and not pd.isna(v) else None
        return d
    return {"historical":[fmt_h(r) for _,r in hist.iterrows()],
            "forecast":  [fmt(r)   for _,r in fcast.iterrows()],
            "n_train":len(df)}


def compute_predictions(ts_series):
    results = {}
    for name, data in ts_series.items():
        if not data:
            results[name] = {"error":"empty series"}; continue
        df = pd.DataFrame(data)
        df["ds"] = pd.to_datetime(df["ds"])
        print(f"  → Prophet [{name}]: {len(df)} pts")
        results[name] = run_prophet(df)
        n_f = len(results[name].get("forecast",[]))
        if n_f:
            f0 = results[name]["forecast"][0]
            print(f"    +15min yhat={f0['yhat']:.4f} [{f0['yhat_lower']:.4f},{f0['yhat_upper']:.4f}]")
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  CSV EXPORT
# ══════════════════════════════════════════════════════════════════════════════
def export_csvs(ts_series):
    folder_in  = os.path.join(SCRIPT_DIR, "data_pret_pour_prediction")
    folder_out = os.path.join(SCRIPT_DIR, "data_after_prediction")
    os.makedirs(folder_in,  exist_ok=True)
    os.makedirs(folder_out, exist_ok=True)
    for name, data in ts_series.items():
        if not data: continue
        df = pd.DataFrame(data)
        df["ds"] = pd.to_datetime(df["ds"])
        df.to_csv(os.path.join(folder_in, f"{name}_train.csv"), index=False)
        if PROPHET_AVAILABLE:
            res = run_prophet(df)
            if "error" not in res:
                rows  = [{"ds":r["ds"],"type":"historical","actual":r.get("actual"),
                          "yhat":r["yhat"],"yhat_lower":r["yhat_lower"],"yhat_upper":r["yhat_upper"]}
                         for r in res["historical"]]
                rows += [{"ds":r["ds"],"type":"forecast","actual":None,
                          "yhat":r["yhat"],"yhat_lower":r["yhat_lower"],"yhat_upper":r["yhat_upper"]}
                         for r in res["forecast"]]
                pd.DataFrame(rows).to_csv(
                    os.path.join(folder_out, f"{name}_forecast.csv"), index=False)
        print(f"  ✓ CSV: {name} ({len(data)} pts)")
    print(f"  Training CSVs → {folder_in}")
    print(f"  Forecast CSVs → {folder_out}")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════
def get_data():
    if _cache: return _cache
    if not METRICS_ENGINE_OK:
        return {"error": "metrics_engine.py not found next to app.py"}
    path = find_log()
    if not path:
        if os.path.exists(METRICS_FILE):
            print("⚠  No log — loading cached metrics_computed.json")
            with open(METRICS_FILE) as f:
                d = json.load(f)
            _cache.update(d)
            return _cache
        return {"error": "No log file found — place open5gs_pfe_pure.log next to app.py"}

    print(f"✓ Computing metrics from: {path}")
    metrics  = compute_metrics(path)
    save_metrics(metrics, METRICS_FILE)
    ts_series = metrics.pop("_ts_series", {})

    print("✓ Running Prophet…")
    try:
        metrics["predictions"] = compute_predictions(ts_series)
    except Exception as e:
        print(f"⚠  Prophet error: {e}")
        metrics["predictions"] = {"error": str(e)}

    print(f"✓ Ready — global_health={metrics['kpis']['global_health']}")
    _cache.update(metrics)
    return _cache


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/")
def index(): return send_from_directory("static","index.html")

@app.route("/api/data")
def api_data(): return jsonify(get_data())

@app.route("/api/predictions")
def api_predictions():
    d = get_data()
    return jsonify(d.get("predictions", {}))

@app.route("/api/metrics")
def api_metrics():
    if os.path.exists(METRICS_FILE):
        with open(METRICS_FILE) as f: return jsonify(json.load(f))
    return jsonify({"error":"metrics_computed.json not yet generated"}), 404

@app.route("/api/refresh")
def api_refresh():
    _cache.clear(); return jsonify({"ok":True})

@app.route("/api/export-csv")
def api_export_csv():
    if not METRICS_ENGINE_OK: return jsonify({"error":"metrics_engine.py missing"}),500
    path = find_log()
    if not path: return jsonify({"error":"Log not found"}),404
    try:
        metrics   = compute_metrics(path)
        ts_series = metrics.pop("_ts_series", {})
        export_csvs(ts_series)
        return jsonify({"status":"ok",
            "input":  os.path.join(SCRIPT_DIR,"data_pret_pour_prediction"),
            "output": os.path.join(SCRIPT_DIR,"data_after_prediction"),
            "series": {k:len(v) for k,v in ts_series.items()}})
    except Exception as e:
        return jsonify({"error":str(e)}),500

@app.route("/api/status")
def api_status():
    path = find_log() if METRICS_ENGINE_OK else None
    return jsonify({
        "metrics_engine":    METRICS_ENGINE_OK,
        "prophet_available": PROPHET_AVAILABLE,
        "log_found":    path is not None,
        "log_path":     path,
        "log_name":     os.path.basename(path) if path else None,
        "metrics_cached": bool(_cache),
        "metrics_file_exists": os.path.exists(METRICS_FILE),
        "script_dir": SCRIPT_DIR, "cwd": os.getcwd(),
    })


# ══════════════════════════════════════════════════════════════════════════════
#  STARTUP
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("  AI Platform 5G — PFE 2026")
    print("  Open5GS v2.7.7 + UERANSIM v3.2.6")
    print("=" * 60)

    if not METRICS_ENGINE_OK:
        print("✗ metrics_engine.py missing"); sys.exit(1)

    path = find_log()
    if not path:
        print("✗ Log not found — place open5gs_pfe_pure.log next to app.py"); sys.exit(1)

    print(f"✓ Log:     {path}")
    print(f"✓ Prophet: {'OK' if PROPHET_AVAILABLE else 'NOT installed'}")

    print("\n── Step 1: Metrics from log ─────────────────────────────────")
    metrics   = compute_metrics(path)
    save_metrics(metrics, METRICS_FILE)
    ts_series = metrics.get("_ts_series", {})
    if "_ts_series" not in metrics:
        from metrics_engine import compute_metrics as _cm
        ts_series = _cm(path).get("_ts_series", {})

    print("\n── Step 2: Prophet-ready CSVs ───────────────────────────────")
    export_csvs(ts_series)

    print("\n── Step 3: Server ───────────────────────────────────────────")
    print("✓ http://0.0.0.0:5000")
    print("✓ /api/status | /api/metrics | /api/predictions | /api/export-csv")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
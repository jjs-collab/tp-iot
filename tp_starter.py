"""
TP Sécurité IoT (version longue, ~10-13h) — Squelette de démarrage
====================================================================
Complétez les fonctions marquées TODO, dans l'ordre du document
TP_securite_iot.md. Chaque section du fichier correspond à une partie
de l'énoncé.
"""

import json
import re
import math
import hashlib
import hmac as hmac_lib
from collections import defaultdict, Counter, deque
from dataclasses import dataclass, asdict, field
from sre_parse import parse
from typing import Literal, Any
from itertools import chain

Protocol = Literal["zigbee", "zwave", "ha"]
VALID_PROTOCOLS = ("zigbee", "zwave", "ha")


@dataclass
class Metric:
    device_id: str
    protocol: Protocol
    metric_name: str
    metric_value: float | None
    safety_critical: bool
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def make_metric(
    device_id: str,
    protocol: Protocol,
    metric_name: str,
    metric_value: float | None = None,
    safety_critical: bool = False,
    raw: dict[str, Any] | None = None,
) -> dict:
    if protocol not in VALID_PROTOCOLS:
        raise ValueError(f"protocol invalide: {protocol!r}")
    if metric_value is not None:
        metric_value = float(metric_value)
    return Metric(
        device_id=str(device_id),
        protocol=protocol,
        metric_name=metric_name,
        metric_value=metric_value,
        safety_critical=bool(safety_critical),
        raw=raw or {},
    ).to_dict()



# ============================================================
# PARTIE 2 — PARSERS PROTOCOLAIRES
# ============================================================

def parse_zigbee_line(line: str) -> dict | None:
    ZIGBEE_LINE_RE = re.compile(r"topic 'zigbee2mqtt/([^']+)',\s*payload '(\{.*\})'")
    message = ZIGBEE_LINE_RE.search(line)
    if message:
        device = message.group(1)                 # capteur_salon
        data = json.loads(message.group(2))       # dict Python
        return {
            "name" : device,
            "payload" : data
        }
    return None



def parse_zwave_line(line: str) -> dict | None:
    if "Metadata updated" in line:
        return None
    ZWAVE_RE = re.compile(
        r"\[\s*Node\s+(?P<node>\d+)\]\s+Value updated.*?"
        r"-\s*(?P<label>[A-Za-z][\w ]*?)\s+"
        r"(?P<old>-?\d+(?:\.\d+)?)\s*=\s*>\s*(?P<new>-?\d+(?:\.\d+)?)"
    )

    m = ZWAVE_RE.search(line)
    if m:
        node = m["node"]               # "003"
        label = m["label"]             # "Power"
        old = float(m["old"])          # 14.5
        new = float(m["new"])          # 30.7
        return {"node" : node, "label" : label, "old" : old, "new" : new}
    return None



def parse_ha_line(line: str) -> dict | None:
    jsonPayload = json.loads(line)
    if not ("state" in jsonPayload):
        return None
    try:
        value = int(jsonPayload["state"])
        name = jsonPayload["entity_id"]
        unit = jsonPayload["unit"]
        return {
            "name" :name,
            "value" : value,
            "unit" : unit,
            "raw" : jsonPayload
        }
    except ValueError:
        return None



# ============================================================
# PARTIE 3 — NORMALISATION SÉMANTIQUE
# ============================================================

ZIGBEE_KNOWN_FIELDS = {
    "power": "power",
    "current": "current",
    "voltage": "voltage",
    "energy": "energy",
    "battery": "battery",
    "linkquality": "link_quality",
}

# Champs à considérer comme "safety_critical" : voir Exercice 3.4.
# Un événement marqué ainsi doit toujours passer, quel que soit le
# filtre deadband (Property 2 du papier de recherche associé).
SAFETY_CRITICAL_FIELDS = {"alarm", "tamper", "contact"}


def normalize_zigbee(parsed: dict) -> list[dict]:
    """Voir énoncé Partie 3, Exercices 3.1 à 3.4."""
    payload = parsed["payload"]
    device_id = parsed["name"]
    eventList = []
    for event in payload:
        if event in SAFETY_CRITICAL_FIELDS:
            normalized_event = make_metric(
                device_id=device_id,
                protocol="zigbee",
                metric_name=event,
                metric_value=payload[event],
                raw=payload,
                safety_critical=True,
            )
            eventList.append(normalized_event)
        elif event in ZIGBEE_KNOWN_FIELDS:
            normalized_event = make_metric(
                device_id=device_id,
                protocol="zigbee",
                metric_name=ZIGBEE_KNOWN_FIELDS[event],
                metric_value=payload[event],
                raw=payload
            )
            eventList.append(normalized_event)
        else:
            normalized_event = make_metric(
                device_id=device_id,
                protocol="zigbee",
                metric_name=f"unknown_{event}",
                metric_value=None,
                raw=payload
            )
            eventList.append(normalized_event)
    return eventList


def normalize_zwave(parsed: dict) -> list[dict]:
    old = parsed["old"]
    new = parsed["new"]
    node = parsed["node"]
    label = parsed["label"]
    normalized_event = make_metric(
        device_id=node,
        protocol="zwave",
        metric_name=label,
        metric_value=new,
        raw=parsed
    )
    return [normalized_event]


def normalize_ha(parsed: dict) -> list[dict]:
    device = parsed["name"]
    value  = parsed["value"]
    unit = parsed["unit"]
    normalized_event = make_metric(
        device_id=device,
        protocol="ha",
        metric_name=unit,
        metric_value=value,
        raw=parsed
    )
    return [normalized_event]
    # TODO
    raise NotImplementedError


# ============================================================
# PARTIE 4 — PARSER STREAMING (fichiers volumineux)
# ============================================================

def naive_ha_load(path: str):
    """
    Tentative naïve : charger tout le fichier avec json.load().
    Utilisée en Partie 4 uniquement pour CONSTATER l'échec — ne modifiez
    pas cette fonction, elle est censée lever une exception sur un
    fichier HA réel (objets JSON concaténés, pas un tableau unique).
    """
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def streaming_parse_ha(path: str):
    depth = 0
    buffer = []
    objects = []
    with open(path, encoding='utf-8') as f:
        for line in f:
            if "{" in line:
                depth+=1
            if "}" in line:
                depth -= 1
            buffer.append(line)
            if depth == 0 and len(buffer) != 0:
                result = "".join(buffer)
                jsonPayload = json.loads(result)
                buffer.clear()
                yield jsonPayload

    """
    Implémentation de l'Algorithme 1 (parseur par comptage d'accolades).
    Doit produire un générateur qui yield chaque objet JSON top-level
    complet, au fur et à mesure, sans jamais garder en mémoire plus
    que l'objet en cours de construction.

    Voir énoncé Partie 4, Exercice 4.2.
    """
    # TODO : buf="", depth=0, incrémenter sur '{', décrémenter sur '}',
    # yield json.loads(buf) quand depth revient à 0


# ============================================================
# PARTIE 5 — FILTRE DEADBAND
# ============================================================

def deadband_filter(events: list[dict], delta: float) -> list[dict]:
    """
    Exercices 5.1 et 5.2.
    Pour chaque (device_id, metric_name), ne transmet un événement que si
    sa valeur diffère d'au moins `delta` (en valeur absolue) de la dernière
    valeur TRANSMISE. L'ordre d'origine des événements est conservé.

    - safety_critical=True : toujours transmis (Property 2).
    - metric_value is None (champs unknown_*) : toujours transmis, rien à
      comparer et on ne jette jamais un champ imprévu (Property 1).
    - premier événement d'un (device_id, metric_name) : toujours transmis.
    """
    last_sent: dict[tuple[str, str], float] = {}
    filtered_events = []
    for event in events:
        key = (event["device_id"], event["metric_name"])
        value = event["metric_value"]
        if event["safety_critical"] or value is None:
            filtered_events.append(event)
            continue
        if key not in last_sent or abs(value - last_sent[key]) >= delta:
            filtered_events.append(event)
            last_sent[key] = value
    return filtered_events


def deadband_sensitivity(events: list[dict],
                         deltas: tuple[float, ...] = (0.5, 1.0, 2.0, 5.0)) -> list[dict]:
    """
    Exercice 5.3 — Analyse de sensibilité.
    Pour chaque delta, retourne {"delta", "remaining", "filtered_pct"}
    où filtered_pct est le pourcentage d'événements supprimés (0-100).
    """
    total = len(events)
    table = []
    for delta in deltas:
        remaining = len(deadband_filter(events, delta))
        pct = 100 * (total - remaining) / total if total else 0.0
        table.append({"delta": delta, "remaining": remaining, "filtered_pct": round(pct, 1)})
    return table


# ============================================================
# PARTIE 6 — RÈGLES DE DÉTECTION DE BASE
# ============================================================

def detect_power_surge(events: list[dict], threshold_w: float = 2000) -> list[dict]:
    """Voir énoncé Partie 6, Exercice 6.1."""
    alerts = []
    for event in events:
        metric = event["metric_name"]
        metric_value = event["metric_value"]
        if metric == "power" and metric_value > threshold_w:
            alerts.append(event)
    return alerts



def detect_replay(events: list[dict], window: int = 3) -> list[dict]:
    replays = []
    dev_id = {}
    for event in events:
        if event["metric_value"] is None or event["safety_critical"]:
            continue
        data_tuple = (event["device_id"], event["metric_name"])
        if data_tuple in dev_id:
            last_event = dev_id[data_tuple][-1]
            if last_event["metric_value"] == event["metric_value"]:
                dev_id[data_tuple].append(event)
                if len(dev_id[data_tuple]) == window:
                    replays.append(event)
            else:
                dev_id[data_tuple] = [event]
        else:
            dev_id[data_tuple] = [event]
    return replays


def detect_rogue_device(events: list[dict], known_devices: set[str]) -> list[dict]:
    """Voir énoncé Partie 6, Exercice 6.3."""
    alerts = []
    seen = set()
    for event in events:
        device = event["device_id"]
        if device not in known_devices and device not in seen:
            seen.add(device)
            alerts.append(event)
    return alerts


def detect_event_storm(message_device_ids: list[str], window_size: int = 20,
                        max_per_device: int = 8) -> list[dict]:
    """
    Partie 6, Exercice 6.4.
    Alerte si un même device_id produit plus de `max_per_device` messages
    sur une fenêtre glissante des `window_size` derniers messages TOUS
    DEVICES CONFONDUS.

    Attention : on reçoit la liste des device_id au niveau MESSAGE brut
    (un id par message, avant normalize_zigbee), pas les événements
    normalisés (un message Zigbee en donne 8 à 11).
    """
    storms = []
    window = deque(maxlen=window_size)
    in_storm = set()
    for index, device in enumerate(message_device_ids):
        window.append(device)
        counts = Counter(window)
        in_storm = {d for d in in_storm if counts[d] > max_per_device}
        if counts[device] > max_per_device and device not in in_storm:
            in_storm.add(device)
            storms.append({"device_id": device, "index": index, "count": counts[device]})
    return storms


# ============================================================
# PARTIE 8 — PSEUDONYMISATION HMAC
# ============================================================

def naive_hash_device_id(name: str) -> str:
    """Voir énoncé Partie 8, Exercice 8.1 (à ne PAS utiliser en prod)."""
    return hashlib.sha256(name.encode()).hexdigest()[:20]


def hmac_pseudonymize(protocol: str, name: str, secret: bytes) -> str:
    """
    Voir énoncé Partie 8, Exercice 8.2.
    Doit reproduire : HMAC-SHA256(secret, "protocol:name")[:20]
    """
    message = f"{protocol}:{name}".encode()
    return hmac_lib.new(secret, message, hashlib.sha256).hexdigest()[:20]


def dictionary_attack(observed_hashes: set[str], dictionary: list[str], hash_fn) -> dict:
    """
    Voir énoncé Partie 8, Exercice 8.3.
    `hash_fn` est un callable à UN SEUL argument (le nom deviné) — utilisez
    une lambda pour fixer protocole/secret, ex:
        dictionary_attack(observed, dico, lambda name: naive_hash_device_id(name))
    Essaie de retrouver les valeurs d'origine derrière `observed_hashes`
    en précalculant hash_fn(guess) pour chaque `guess` du dictionnaire.
    """
    precomputed = {}
    for guess in dictionary:
        precomputed[hash_fn(guess)] = guess
    found = {}
    for observed in observed_hashes:
        if observed in precomputed:
            found[observed] = precomputed[observed]
    return found


# ============================================================
# PARTIE 9 — DÉTECTION PAR ENTROPIE (canaux cachés)
# ============================================================

def shannon_entropy(s: str) -> float:
    """
    Voir énoncé Partie 9, Exercice 9.1.
    H(s) = -sum(p_c * log2(p_c)) pour chaque caractère c de s.
    """
    if len(s) == 0:
        return 0.0
    entropy = 0.0
    for count in Counter(s).values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy


def detect_high_entropy_unknown(events: list[dict], threshold: float = 4.5,
                                 min_length: int = 8) -> list[dict]:
    """
    Voir énoncé Partie 9, Exercice 9.2.
    Ne s'applique qu'aux événements "unknown_*" (metric_value is None)
    dont la valeur brute est une chaîne de caractères.
    """
    alerts = []
    for event in events:
        name = event["metric_name"]
        if not name.startswith("unknown_") or event["metric_value"] is not None:
            continue
        value = event["raw"].get(name[len("unknown_"):])
        if isinstance(value, str) and len(value) >= min_length:
            if shannon_entropy(value) > threshold:
                alerts.append(event)
    return alerts


# ============================================================
# PARTIE 10 — EXTENSION MITRE (A10-A15)
# ============================================================

MITRE_ARTIFACT_LABELS = {
    "unmapped_linux_cmd": "A10 Privilege Escalation",
    "unmapped_net_cmd": "A11 Reverse Shell",
    "unmapped_persist_cmd": "A12 Persistence Cron/Systemd",
    "unmapped_cred_access": "A13 Credential Access",
    "unmapped_download_cmd": "A14 Command and Control / Dropper",
    "unmapped_lateral_cmd": "A15 Lateral Movement",
}


def detect_mitre_artifact(events: list[dict]) -> list[dict]:
    """Voir énoncé Partie 10, Exercice 10.1."""
    alerts = []
    for event in events:
        name = event["metric_name"]
        if not name.startswith("unknown_"):
            continue
        field = name[len("unknown_"):]
        for prefix, technique in MITRE_ARTIFACT_LABELS.items():
            if field.startswith(prefix):
                alerts.append({"technique": technique, "event": event})
    return alerts


# ============================================================
# PARTIE 11 — PIPELINE COMPLET ET ÉVALUATION À GRANDE ÉCHELLE
# ============================================================

def run_pipeline(zigbee_path, zwave_path, delta=1.0, known_devices=None,
                  power_threshold=2000):
    """
    Pipeline complet à assembler en Partie 11.
    Doit retourner un dictionnaire de métriques exploitable pour le
    mini-rapport d'évaluation (Exercice 11.2).
    """
    events = []
    message_device_ids = []
    with open(zigbee_path, encoding="utf-8") as f:
        for line in f:
            parsed = parse_zigbee_line(line)
            if parsed:
                message_device_ids.append(parsed["name"])
                events.extend(normalize_zigbee(parsed))
    with open(zwave_path, encoding="utf-8") as f:
        for line in f:
            parsed = parse_zwave_line(line)
            if parsed:
                events.extend(normalize_zwave(parsed))

    unknown_count = sum(1 for e in events if e["metric_name"].startswith("unknown_"))
    filtered = deadband_filter(events, delta)

    replay_before = detect_replay(events)
    replay_after = detect_replay(filtered)
    power_surge = detect_power_surge(filtered, power_threshold)
    rogue_device = detect_rogue_device(filtered, known_devices) if known_devices is not None else []
    event_storm = detect_event_storm(message_device_ids)
    entropy = detect_high_entropy_unknown(filtered)
    mitre = detect_mitre_artifact(filtered)

    return {
        "events_raw": len(events),
        "events_unknown": unknown_count,
        "unknown_pct": round(100 * unknown_count / len(events), 1) if events else 0.0,
        "events_after_deadband": len(filtered),
        "filtered_pct": round(100 * (len(events) - len(filtered)) / len(events), 1) if events else 0.0,
        "alerts_power_surge": len(power_surge),
        "alerts_replay_before_deadband": len(replay_before),
        "alerts_replay_after_deadband": len(replay_after),
        "alerts_rogue_device": len(rogue_device),
        "alerts_event_storm": len(event_storm),
        "alerts_entropy": len(entropy),
        "alerts_mitre": len(mitre),
        "alerts": {
            "power_surge": power_surge,
            "replay": replay_before,
            "rogue_device": rogue_device,
            "event_storm": event_storm,
            "entropy": entropy,
            "mitre": mitre,
        },
    }


if __name__ == "__main__":
    KNOWN_DEVICES = {
        "zigbee_prise_5", "zigbee-switch-inwall-4", "zigbee-alarm-1",
        "zigbee-pir-1", "node_002", "node_003",
    }
    # Décommentez au fur et à mesure de votre progression :
    result = run_pipeline("data/zigbee_large_sample.log",
                          "data/zwave_large_sample.log",
                          delta=1.0, known_devices=KNOWN_DEVICES)
    result.pop("alerts")
    print(result)

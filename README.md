# 📡 net-monitor

Moniteur de trafic réseau et de connexions actives en temps réel — projet éducatif réalisé dans le cadre du Bac Pro CIEL.

## Fonctionnalités

- Mesure de la bande passante en temps réel (↓ reçu / ↑ envoyé)
- Liste des connexions TCP/UDP actives avec processus associé
- Détection de ports suspects (Metasploit, backdoors, Tor…)
- Affichage des connexions en écoute (LISTEN)

## Installation

```bash
git clone https://github.com/thedevnoxa/net-monitor
cd net-monitor
pip install -r requirements.txt
```

**requirements.txt**
```
psutil>=5.9.0
```

## Utilisation

```bash
# Surveiller la bande passante (rafraîchi toutes les secondes)
python3 net_monitor.py

# Intervalle personnalisé
python3 net_monitor.py --interval 2

# Afficher les connexions actives
python3 net_monitor.py --connections

# Limiter à 10 échantillons
python3 net_monitor.py --count 10
```

## Exemple de sortie

```
[*] Network Monitor — 2026-04-19 14:00:00
[*] Monitoring bandwidth (interval: 1.0s) — Ctrl+C to stop

──────────────────────────────────────────────────────────────────────
  INTERFACE            ↓ RECV/s       ↑ SENT/s       TOTAL ↓        TOTAL ↑
──────────────────────────────────────────────────────────────────────
  14:00:01  245.3 KB       12.1 KB        1.2 GB         320.4 MB

$ python3 net_monitor.py --connections

  Total connections : 42
  Established       : 18
  Listening         : 12

  PROTO  LOCAL                    REMOTE                   STATUS         PROCESS
  ────────────────────────────────────────────────────────
  TCP    0.0.0.0:22               -                        LISTEN         sshd
  TCP    192.168.1.5:54231        142.250.75.46:443        ESTABLISHED    firefox
```

## Stack

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)

---
*Projet réalisé par [Noxa](https://github.com/thedevnoxa) — Bac Pro CIEL*

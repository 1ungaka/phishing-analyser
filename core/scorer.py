def calculate_threat_score(parsed, vt_results=None):
    score = 0
    findings = []

    # Spoofing indicators
    for flag in parsed["spoofing"]:
        score += 25
        findings.append({"severity": "HIGH", "finding": flag})

    # Dangerous attachments
    for att in parsed["attachments"]:
        if att["dangerous"]:
            score += 30
            findings.append({
                "severity": "CRITICAL",
                "finding": f"Dangerous attachment: {att['filename']} ({att['extension']})"
            })
        else:
            score += 5
            findings.append({
                "severity": "LOW",
                "finding": f"Attachment present: {att['filename']}"
            })

    # Suspicious keywords
    if len(parsed["keywords_found"]) >= 4:
        score += 20
        findings.append({
            "severity": "HIGH",
            "finding": f"Multiple social engineering keywords detected: {', '.join(parsed['keywords_found'][:5])}"
        })
    elif len(parsed["keywords_found"]) >= 1:
        score += 10
        findings.append({
            "severity": "MEDIUM",
            "finding": f"Suspicious keywords found: {', '.join(parsed['keywords_found'])}"
        })

    # Suspicious links
    suspicious_links = [l for l in parsed["links"] if l["suspicious"]]
    if suspicious_links:
        score += 20
        findings.append({
            "severity": "HIGH",
            "finding": f"{len(suspicious_links)} suspicious URL(s) detected with unusual domain patterns"
        })

    # VirusTotal URL results
    if vt_results:
        for url, result in vt_results.items():
            if result.get("malicious", 0) > 0:
                score += 35
                findings.append({
                    "severity": "CRITICAL",
                    "finding": f"URL flagged malicious by {result['malicious']} VirusTotal vendors: {url[:60]}"
                })

    # No links or attachments — lower risk
    if not parsed["links"] and not parsed["attachments"]:
        findings.append({"severity": "LOW", "finding": "No links or attachments found"})

    score = min(score, 100)

    if score >= 70:
        threat_level = "CRITICAL"
    elif score >= 45:
        threat_level = "HIGH"
    elif score >= 20:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    return {
        "score": score,
        "threat_level": threat_level,
        "findings": findings,
    }

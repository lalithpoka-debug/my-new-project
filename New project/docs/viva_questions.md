# Viva Questions with Answers

## 1. What is an Intrusion Detection System?

An Intrusion Detection System is a security tool that monitors network or system activity to detect suspicious behavior, attacks, or policy violations.

## 2. What is the difference between IDS and IPS?

An IDS only detects and reports suspicious activity, while an IPS can also take action to block or stop the attack.

## 3. What is the difference between signature-based and anomaly-based detection?

Signature-based detection matches known attack patterns. Anomaly-based detection looks for unusual behavior compared to normal traffic patterns.

## 4. Why did you use both signature and anomaly detection?

Using both methods improves coverage. Signature rules detect known attacks quickly, while anomaly detection helps identify unknown or unexpected behavior.

## 5. Why is Npcap required on Windows?

Npcap provides packet capture support for Windows. Scapy uses it to access live network traffic.

## 6. What is Scapy used for in this project?

Scapy is used to capture packets, inspect protocol fields, and generate demo packets for testing.

## 7. Why are Pandas and NumPy used?

They are used for anomaly detection. Pandas organizes recent packet data into a table-like format, and NumPy helps calculate statistical values like mean and standard deviation.

## 8. What attacks can your IDS detect?

It can detect SYN flood, ICMP flood, TCP port scan, NULL scan, Xmas scan, large UDP broadcast packets, traffic spikes, and abnormal packet sizes.

## 9. What is a SYN flood attack?

A SYN flood is a denial-of-service attack in which an attacker sends a large number of TCP SYN packets to exhaust server resources.

## 10. What is port scanning?

Port scanning is the process of probing multiple ports on a target system to find open services that could be exploited.

## 11. What is a NULL scan?

A NULL scan is a TCP scan where no flags are set. It is considered suspicious because it is not part of normal communication.

## 12. What is an Xmas scan?

An Xmas scan is a TCP scan where FIN, PSH, and URG flags are set together. It is often used to probe systems stealthily.

## 13. How does anomaly detection work in your project?

The project keeps a short history of packets and compares the current packet against recent traffic. If the packet rate, target spread, or packet size is much higher than normal, an anomaly alert is generated.

## 14. How do you avoid duplicate alerts?

The detection engine uses a cooldown mechanism. If the same rule is triggered repeatedly for the same source and destination within a short time, duplicate alerts are suppressed.

## 15. What are the limitations of this project?

The project uses simple rules and statistical thresholds, so it may miss advanced attacks or produce false positives under unusual but legitimate traffic conditions.

## 16. How can this project be improved?

It can be improved by adding machine learning, more signatures, automated blocking, database storage, and advanced visualizations.

## 17. Why did you include a demo mode?

Demo mode makes the project easy to present because it generates realistic normal and malicious traffic even when live attack traffic is unavailable.

## 18. Can this IDS stop attacks automatically?

No. This version is an IDS, not an IPS. It detects and alerts, but it does not block traffic automatically.

## 19. Why is logging important in an IDS?

Logs provide evidence of detected events, help in incident investigation, and allow results to be included in reports and presentations.

## 20. What is the role of the dashboard?

The dashboard gives a live view of packet counts, protocols, top IPs, and alerts so that the user can monitor the network more easily than by reading raw console output alone.


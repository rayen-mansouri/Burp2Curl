# Burp2Curl

Just vibecoded a Python tool to convert Burp Suite's intercepted request into a ready‑to‑use `curl` command. Helps in testing, parameter manipulation, and looping.

**Why not just use Burp's repeater?**  
Because `curl` works in scripts – loop over payloads, fuzz parameters, automate your testing pipeline.

## Install (one command)

git clone https://github.com/rayen-mansouri/Burp2Curl.git && cd Burp2Curl


Usage:

./burp2curl                # paste a request (Ctrl+D to finish)

./burp2curl request.txt    # from file

cat request.txt | ./burp2curl   # from pipe

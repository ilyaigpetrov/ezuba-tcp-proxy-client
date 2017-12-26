sudo iptables -t nat -D OUTPUT -p tcp -m tcp -j REDIRECT --dport 80 --to-port 2222
sudo iptables -t nat -A OUTPUT -p tcp -m tcp -j REDIRECT --dport 80 --to-port 2222

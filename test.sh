#!/bin/bash
# Automated ft_nmap with firewall rules

# Add rule to block RST packets
echo "Adding iptables rule to block RST packets..."
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 32768:61000 -j DROP

# Run the scan
echo "Running ft_nmap scan..."
sudo ./ft_nmap "$@"

# Remove the rule
echo "Removing iptables rule..."
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST --sport 32768:61000 -j DROP

echo "Scan complete!"
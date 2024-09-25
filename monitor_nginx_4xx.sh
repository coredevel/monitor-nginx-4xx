#!/bin/bash

# Path to the NGINX access log
LOGFILE="/var/log/nginx/access.log"

# Temporary file to store IP and error count
TEMPFILE="/tmp/nginx_4xx_ips.txt"

# Custom nftables table, set, and chain
NFT_TABLE="nginx-ban-table"
NFT_SET="addr-set-nginx-ban"
NFT_CHAIN="nginx-ban-chain"

# Function to initialize nftables custom rules if they don't exist
initialize_nftables() {
    # Check if the table exists
    if ! sudo nft list tables | grep -q $NFT_TABLE; then
        echo "Setting up nftables custom table, set, and chain for NGINX ban."

        # Create the custom table, set, and chain
        sudo nft add table inet $NFT_TABLE
        sudo nft add set inet $NFT_TABLE $NFT_SET { type ipv4_addr\; flags timeout\; timeout 24h\; }
        sudo nft add chain inet $NFT_TABLE $NFT_CHAIN { type filter hook input priority filter\; policy accept\; }
        sudo nft add rule inet $NFT_TABLE $NFT_CHAIN ip saddr @$NFT_SET drop
    fi
}

# Function to ban IP by adding it to the custom nftables set
ban_ip() {
    local ip=$1
    echo "Banning IP: $ip for exceeding 3 4xx errors"

    # Add the IP to the addr-set-nginx-ban set
    sudo nft add element inet $NFT_TABLE $NFT_SET { $ip }

    # Remove the IP from the temp file to reset its count
    sed -i "/^$ip/d" "$TEMPFILE"
}

# Function to re-add previously tracked IPs (in the temp file) to nftables on initialization
sync_existing_bans() {
    echo "Syncing previously tracked IPs with nftables..."
    while read -r line; do
        ip=$(echo "$line" | awk '{print $1}')
        count=$(echo "$line" | awk '{print $2}')

        # If the count is 3 or more, ensure the IP is added to nftables
        if [ "$count" -ge 3 ]; then
            ban_ip "$ip"
        fi
    done < "$TEMPFILE"
}

# Ensure the temp file exists
touch $TEMPFILE

# Initialize nftables
initialize_nftables

# Sync any pre-existing bans from the temp file into nftables
sync_existing_bans

# Infinite loop to continuously monitor the log file
tail -F $LOGFILE | while read -r line; do
    # Use awk to extract IP and status code in one step
    read ip status <<< $(echo "$line" | awk '
    {
        match($0, /^([0-9.]+) - - \[([^\]]+)\] "([^"]+)" ([0-9]+) ([0-9]+) "([^"]*)" "([^"]*)"/, parts);
        ip = parts[1];
        status = parts[4];
        print ip, status;
    }')

    # Check if the status code is a 4xx error
    if [[ $status =~ ^4[0-9][0-9]$ ]]; then
        # Read the current count for the IP from the temp file
        count=$(grep -w "$ip" "$TEMPFILE" | awk '{print $2}')

        # If the IP is new, set count to 1, otherwise increment the count
        if [ -z "$count" ]; then
            count=1
        else
            count=$((count + 1))
        fi

        # Update the temp file with the new count
        sed -i "/^$ip/d" "$TEMPFILE" # Remove any existing entry for the IP
        echo "$ip $count" >> "$TEMPFILE"

        # If the count exceeds or equals 3, ban the IP and remove it from the temp file
        if [ "$count" -ge 3 ]; then
            ban_ip "$ip"
        fi
    fi
done

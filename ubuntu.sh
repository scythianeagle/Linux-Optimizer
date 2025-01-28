#!/bin/bash

# Green, Yellow & Red Messages.
green_msg() {
    tput setaf 2
    echo "[*] ----- $1"
    tput sgr0
}

yellow_msg() {
    tput setaf 3
    echo "[*] ----- $1"
    tput sgr0
}

red_msg() {
    tput setaf 1
    echo "[*] ----- $1"
    tput sgr0
}


# Declare Paths & Settings.
SYS_PATH="/etc/sysctl.conf"
PROF_PATH="/etc/profile"
SSH_PORT=""
SSH_PATH="/etc/ssh/sshd_config"
SWAP_PATH="/swapfile"
SWAP_SIZE=1G


# Root
check_if_running_as_root() {
    ## If you want to run as another user, please modify $EUID to be owned by this user
    if [[ "$EUID" -ne '0' ]]; then
      echo 
      red_msg 'Error: You must run this script as root!'
      echo 
      sleep 0.5
      exit 1
    fi
}


# Check Root
check_if_running_as_root
sleep 0.5


# Ask Reboot
ask_reboot() {
    yellow_msg 'Reboot now? (Recommended) (y/n)'
    echo 
    while true; do
        read -r choice
        echo 
        if [[ "$choice" == 'y' || "$choice" == 'Y' ]]; then
            sleep 0.5
            reboot
            exit 0
        fi
        if [[ "$choice" == 'n' || "$choice" == 'N' ]]; then
            break
        fi
    done
}


# Update & Upgrade & Remove & Clean
complete_update() {
    echo 
    yellow_msg 'Updating the System... (This can take a while.)'
    echo 
    sleep 0.5

     apt -q update
     apt -y upgrade
     apt -y full-upgrade
     apt -y autoremove
    sleep 0.5

    ## Again :D
     apt -y -q autoclean
     apt -y clean
     apt -q update
     apt -y upgrade
     apt -y full-upgrade
     apt -y autoremove --purge

    echo 
    green_msg 'System Updated & Cleaned Successfully.'
    echo 
    sleep 0.5
}


# Disable Terminal Ads
disable_terminal_ads() {
    echo 
    yellow_msg 'Disabling Terminal Ads...'
    echo 
    sleep 0.5

    sed -i 's/ENABLED=1/ENABLED=0/g' /etc/default/motd-news
    pro config set apt_news=false

    echo 
    green_msg 'Terminal Ads Disabled.'
    echo 
    sleep 0.5
}


# Install XanMod Kernel
install_xanmod() {
    echo 
    yellow_msg 'Checking XanMod...'
    echo 
    sleep 0.5

    if uname -r | grep -q 'xanmod'; then
        green_msg 'XanMod is already installed.'
        echo 
        sleep 0.5
    else
        echo 
        yellow_msg 'XanMod not found. Installing XanMod Kernel...'
        echo 
        sleep 0.5

        ## Update, Upgrade & Install dependencies
         apt update -q
         apt upgrade -y
         apt install wget curl gpg -y

        ## Check the CPU level
        cpu_level=$(awk -f - <<EOF
        BEGIN {
            while (!/flags/) if (getline < "/proc/cpuinfo" != 1) exit 1
            if (/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/) level = 1
            if (level == 1 && /cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/) level = 2
            if (level == 2 && /avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/) level = 3
            if (level == 3 && /avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/) level = 4
            if (level > 0) { print level; exit level + 1 }
            exit 1
        }
EOF
        )

        if [ "$cpu_level" -ge 1 ] && [ "$cpu_level" -le 4 ]; then
            echo 
            yellow_msg "CPU Level: v$cpu_level"
            echo 

            ## Add the XanMod repository key
            # Define a temporary file for the GPG key
            tmp_keyring="/tmp/xanmod-archive-keyring.gpg"

            # Try downloading the GPG key from the XanMod link first
            if ! wget -qO $tmp_keyring https://dl.xanmod.org/archive.key || ! [ -s $tmp_keyring ]; then
                # If the first attempt fails, try the GitLab link
                if ! wget -qO $tmp_keyring https://gitlab.com/afrd.gpg || ! [ -s $tmp_keyring ]; then
                    echo "Both attempts to download the GPG key failed or the file was empty. Exiting."
                    exit 1
                fi
            fi

            # If we reach this point, it means we have a non-empty GPG file
            # Now dearmor the GPG key and move to the final location
             gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg $tmp_keyring

            # Clean up the temporary file
            rm -f $tmp_keyring

            ## Add the XanMod repository
            echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' |  tee /etc/apt/sources.list.d/xanmod-release.list
            
            ## Install XanMod
             apt update -q &&  apt install "linux-xanmod-x64v$cpu_level" -y

            ## Clean up
             apt update -q
             apt autoremove --purge -y
            
            echo 
            green_msg "XanMod Kernel Installed. Reboot to Apply the new Kernel."
            echo 
            sleep 1
        else
            echo 
            red_msg "Unsupported CPU. (Check the supported CPUs at xanmod.org)"
            echo 
            sleep 2
        fi
        
    fi
}


# Install useful packages
installations() {
    echo 
    yellow_msg 'Installing Useful Packages...'
    echo 
    sleep 0.5

    ## Networking packages
     apt -y install apt-transport-https stunnel4 openssh-server bash-completion ca-certificates apt-utils curl nano screen net-tools unzip wget tmux nethogs git pkg-config python3 python3-pip
   
    echo 
    green_msg 'Useful Packages Installed Succesfully.'
    echo 
    sleep 0.5
}


# Enable packages at server boot
#enable_packages() {
#     systemctl enable cron haveged preload
#    echo 
#    green_msg 'Packages Enabled Succesfully.'
#    echo
#    sleep 0.5
#}


## Swap Maker
swap_maker() {
    echo 
    yellow_msg 'Making SWAP Space...'
    echo 
    sleep 0.5

    ## Make Swap
     fallocate -l $SWAP_SIZE $SWAP_PATH  ## Allocate size
     chmod 600 $SWAP_PATH                ## Set proper permission
     mkswap $SWAP_PATH                   ## Setup swap         
     swapon $SWAP_PATH                   ## Enable swap
    echo "$SWAP_PATH   none    swap    sw    0   0" >> /etc/fstab ## Add to fstab
    echo 
    green_msg 'SWAP Created Successfully.'
    echo
    sleep 0.5
}


# SYSCTL Optimization
sysctl_optimizations() {
    ## Make a backup of the original sysctl.conf file
    cp $SYS_PATH /etc/sysctl.conf.bak

    echo 
    yellow_msg 'Default sysctl.conf file Saved. Directory: /etc/sysctl.conf.bak'
    echo 
    sleep 1

    echo 
    yellow_msg 'Optimizing the Network...'
    echo 
    sleep 0.5

    sed -i -e '/fs.file-max/d' \
        -e '/net.ipv4.tcp_dsack/d' \
        -e '/net.ipv4.tcp_slow_start_after_idle/d' \
        -e '/net.ipv4.tcp_window_scaling/d' \
        -e '/net.ipv4.tcp_ecn/d' \
        -e '/net.ipv4.tcp_ecn_fallback/d' \
        -e '/net.ipv4.tcp_syncookies/d' \
        -e '/net.unix.max_dgram_qlen/d' \
        -e '/vm.swappiness/d' \
        -e '/net.ipv4.conf.default.rp_filter/d' \
        -e '/net.ipv4.conf.all.rp_filter/d' \
        -e '/net.ipv4.conf.all.accept_source_route/d' \
        -e '/net.ipv4.conf.default.accept_source_route/d' \
        -e '/net.ipv4.conf.lo.arp_announce/d' \
        -e '/net.ipv4.conf.all.arp_announce/d' \
        -e '/^#/d' \
        -e '/^$/d' \
        "$SYS_PATH"


    ## Add new parameteres. Read More: https://github.com/hawshemi/Linux-Optimizer/blob/main/files/sysctl.conf

cat <<EOF >> "$SYS_PATH"


################################################################
################################################################


# /etc/sysctl.conf
# These parameters in this file will be added/updated to the sysctl.conf file.
# Read More: https://github.com/hawshemi/Linux-Optimizer/blob/main/files/sysctl.conf


net.ipv4.ip_forward=1
net.ipv4.tcp_congestion_control=cubic
#net.core.default_qdisc=fq_codel
net.core.optmem_max=65535
net.ipv4.ip_no_pmtu_disc=1
net.ipv4.tcp_ecn=0
net.ipv4.tcp_frto=2
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=3
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_low_latency=1
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_reordering=3
net.ipv4.tcp_early_retrans=3
net.ipv4.tcp_abort_on_overflow=1
net.core.rmem_default=4194304
net.ipv4.tcp_max_orphans=3276800
net.ipv4.tcp_autocorking=1
fs.file-max=1000000
fs.inotify.max_user_instances=8192
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_rmem=16384 262144 8388608
net.ipv4.tcp_wmem=32768 524288 16777216
net.core.somaxconn=8192
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.wmem_default=2097152
net.ipv4.tcp_max_tw_buckets=5000
net.ipv4.tcp_max_syn_backlog=10240
net.core.netdev_max_backlog=10240
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_notsent_lowat=16384
net.ipv4.ip_forward=1
net.ipv4.tcp_fin_timeout=25
net.ipv4.tcp_mem=65536 131072 262144
net.ipv4.tcp_retries2=8
net.ipv4.udp_mem=65536 131072 262144
net.unix.max_dgram_qlen=50
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv4.conf.default.arp_announce=2
net.ipv4.conf.lo.arp_announce=2
net.ipv4.conf.all.arp_announce=2

# Disable IPv6
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1


################################################################
################################################################


EOF

    sysctl -p
    sysctl --system
    
    echo 
    green_msg 'Network is Optimized.'
    echo 
    sleep 0.5
}


# Function to find the SSH port and set it in the SSH_PORT variable
find_ssh_port() {
    echo 
    yellow_msg "Finding SSH port..."
    echo 
    
    ## Check if the SSH configuration file exists
    if [ -e "$SSH_PATH" ]; then
        ## Use grep to search for the 'Port' directive in the SSH configuration file
        SSH_PORT=$(grep -oP '^Port\s+\K\d+' "$SSH_PATH" 2>/dev/null)

        if [ -n "$SSH_PORT" ]; then
            echo 
            green_msg "SSH port found: $SSH_PORT"
            echo 
            sleep 0.5
        else
            echo 
            green_msg "SSH port is default 22."
            echo 
            SSH_PORT=1899
            sleep 0.5
        fi
    else
        red_msg "SSH configuration file not found at $SSH_PATH"
    fi
}


# Remove old SSH config to prevent duplicates.
remove_old_ssh_conf() {
    ## Make a backup of the original sshd_config file
    cp $SSH_PATH /etc/ssh/sshd_config.bak

    echo 
    yellow_msg 'Default SSH Config file Saved. Directory: /etc/ssh/sshd_config.bak'
    echo 
    sleep 1

    ## Remove these lines
    sed -i -e 's/#UseDNS yes/UseDNS no/' \
        -e 's/#Compression no/Compression yes/' \
        -e 's/Ciphers .*/Ciphers aes256-ctr,chacha20-poly1305@openssh.com/' \
        -e '/MaxAuthTries/d' \
        -e '/MaxSessions/d' \
        -e '/TCPKeepAlive/d' \
        -e '/ClientAliveInterval/d' \
        -e '/ClientAliveCountMax/d' \
        -e '/AllowAgentForwarding/d' \
        -e '/AllowTcpForwarding/d' \
        -e '/GatewayPorts/d' \
        -e '/PermitTunnel/d' \
        -e '/X11Forwarding/d' "$SSH_PATH"

}
# Update SSH config
update_sshd_conf() {
    echo 
    yellow_msg 'Optimizing SSH...'
    echo 
    sleep 0.5

    ## Change port
    echo "Port 1899" | tee -a "$SSH_PATH"

    ## Enable TCP keep-alive messages
    echo "TCPKeepAlive yes" | tee -a "$SSH_PATH"

    ## Configure client keep-alive messages
    echo "ClientAliveInterval 3000" | tee -a "$SSH_PATH"
    echo "ClientAliveCountMax 100" | tee -a "$SSH_PATH"

    ## Allow agent forwarding
    echo "AllowAgentForwarding yes" | tee -a "$SSH_PATH"

    ## Allow TCP forwarding
    echo "AllowTcpForwarding yes" | tee -a "$SSH_PATH"

    ## Enable gateway ports
    echo "GatewayPorts yes" | tee -a "$SSH_PATH"

    ## Enable tunneling
    echo "PermitTunnel yes" | tee -a "$SSH_PATH"

    ## Enable X11 graphical interface forwarding
    echo "X11Forwarding yes" | tee -a "$SSH_PATH"

    ## Restart the SSH service to apply the changes
    systemctl restart ssh

    echo 
    green_msg 'SSH is Optimized.'
    echo 
    sleep 0.5
}


# System Limits Optimizations
limits_optimizations() {
    echo
    yellow_msg 'Optimizing System Limits...'
    echo 
    sleep 0.5

    ## Clear old ulimits
    sed -i '/ulimit -c/d' $PROF_PATH
    sed -i '/ulimit -d/d' $PROF_PATH
    sed -i '/ulimit -f/d' $PROF_PATH
    sed -i '/ulimit -i/d' $PROF_PATH
    sed -i '/ulimit -l/d' $PROF_PATH
    sed -i '/ulimit -m/d' $PROF_PATH
    sed -i '/ulimit -n/d' $PROF_PATH
    sed -i '/ulimit -q/d' $PROF_PATH
    sed -i '/ulimit -s/d' $PROF_PATH
    sed -i '/ulimit -t/d' $PROF_PATH
    sed -i '/ulimit -u/d' $PROF_PATH
    sed -i '/ulimit -v/d' $PROF_PATH
    sed -i '/ulimit -x/d' $PROF_PATH
    sed -i '/ulimit -s/d' $PROF_PATH


    ## Add new ulimits
    ## The maximum size of core files created.
    echo "ulimit -c unlimited" | tee -a $PROF_PATH

    ## The maximum size of a process's data segment
    echo "ulimit -d unlimited" | tee -a $PROF_PATH

    ## The maximum size of files created by the shell (default option)
    echo "ulimit -f unlimited" | tee -a $PROF_PATH

    ## The maximum number of pending signals
    echo "ulimit -i unlimited" | tee -a $PROF_PATH

    ## The maximum size that may be locked into memory
    echo "ulimit -l unlimited" | tee -a $PROF_PATH

    ## The maximum memory size
    echo "ulimit -m unlimited" | tee -a $PROF_PATH

    ## The maximum number of open file descriptors
    echo "ulimit -n 1048576" | tee -a $PROF_PATH

    ## The maximum POSIX message queue size
    echo "ulimit -q unlimited" | tee -a $PROF_PATH

    ## The maximum stack size
    echo "ulimit -s -H 65536" | tee -a $PROF_PATH
    echo "ulimit -s 32768" | tee -a $PROF_PATH

    ## The maximum number of seconds to be used by each process.
    echo "ulimit -t unlimited" | tee -a $PROF_PATH

    ## The maximum number of processes available to a single user
    echo "ulimit -u unlimited" | tee -a $PROF_PATH

    ## The maximum amount of virtual memory available to the process
    echo "ulimit -v unlimited" | tee -a $PROF_PATH

    ## The maximum number of file locks
    echo "ulimit -x unlimited" | tee -a $PROF_PATH


    echo 
    green_msg 'System Limits are Optimized.'
    echo 
    sleep 0.5
}

# Show the Menu
show_menu() {
    echo 
    yellow_msg 'Choose One Option: '
    echo 
    green_msg '1  - Apply Everything + XanMod Kernel. (RECOMMENDED)'
    echo
    green_msg '2  - Install XanMod Kernel.'
    echo 
    green_msg '3  - Complete Update + Useful Packages + Make SWAP + Optimize Network, SSH & System Limits '
    green_msg '4  - Complete Update + Make SWAP + Optimize Network, SSH & System Limits '
    green_msg '5  - Complete Update + Make SWAP + Optimize Network, SSH & System Limits'
    echo 
    green_msg '6  - Complete Update & Clean the OS.'
    green_msg '7  - Install Useful Packages.'
    green_msg '8  - Make SWAP (2Gb).'
    green_msg '9  - Optimize the Network, SSH & System Limits.'
    echo 
    green_msg '10 - Optimize the Network settings.'
    green_msg '11 - Optimize the SSH settings.'
    green_msg '12 - Optimize the System Limits.'
    echo 
#    green_msg '13 - Install & Optimize .'
#    echo 
#    red_msg 'q - Exit.'
#    echo 
}


# Choosing Program
main() {
    while true; do
        show_menu
        read  -r -p 'Enter Your Choice: ' choice
        case $choice in
        1)
            apply_everything

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;

        2)
            complete_update
            sleep 0.5

            install_xanmod
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        3)
            complete_update
            sleep 0.5

            installations_enable_packages
            sleep 0.5

            swap_maker
            sleep 0.5

            sysctl_optimizations
            sleep 0.5

            remove_old_ssh_conf
            sleep 0.5

            update_sshd_conf
            sleep 0.5

            limits_optimizations
            sleep 0.5

#            find_ssh_port
#            _optimizations
#           sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        4)
            complete_update
            sleep 0.5

            swap_maker
            sleep 0.5

            sysctl_optimizations
            sleep 0.5

            remove_old_ssh_conf
            sleep 0.5

            update_sshd_conf
            sleep 0.5

            limits_optimizations
            sleep 0.5

#            find_ssh_port
#            _optimizations
#            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        5)
            complete_update
            sleep 0.5

            swap_maker
            sleep 0.5

            sysctl_optimizations
            sleep 0.5

            remove_old_ssh_conf
            sleep 0.5

            update_sshd_conf
            sleep 0.5

            limits_optimizations
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        6)
            complete_update
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
            
        7)
            complete_update
            sleep 0.5

            installations
            enable_packages
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        8)
            swap_maker
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        9)
            sysctl_optimizations
            sleep 0.5

            remove_old_ssh_conf
            sleep 0.5

            update_sshd_conf
            sleep 0.5

            limits_optimizations
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        10)
            sysctl_optimizations
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ;;
        11)
            remove_old_ssh_conf
            sleep 0.5

            update_sshd_conf
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ;;
        12)
            limits_optimizations
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;

        q)
            exit 0
            ;;

        *)
            red_msg 'Wrong input!'
            ;;
        esac
    done
}


# Apply Everything
apply_everything() {

    complete_update
    sleep 0.5

    disable_terminal_ads
    sleep 0.5

    install_xanmod
    sleep 0.5 

    installations
    enable_packages
    sleep 0.5

    swap_maker
    sleep 0.5

    sysctl_optimizations
    sleep 0.5

    remove_old_ssh_conf
    sleep 0.5

    update_sshd_conf
    sleep 0.5

    limits_optimizations
    sleep 0.5
    
    find_ssh_port
    sleep 0.5
}


main

VAGRANTFILE_API_VERSION = "2"

require File.dirname(__FILE__) + '/vagrant-reboot-plugin'

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
    config.vm.provider "virtualbox" do |vb|
        #vb.gui = true
        vb.customize ["modifyvm", :id, "--memory", "2048"]
        vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
        vb.customize ["modifyvm", :id, "--natdnsproxy1", "on"]
        vb.customize ["modifyvm", :id, "--nicpromisc1", "allow-all"]
        vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
        vb.customize ["setextradata", :id, "VBoxInternal/CPUM/SSE4.1", "1"]
        vb.customize ["setextradata", :id, "VBoxInternal/CPUM/SSE4.2", "1"]
    end
    
    # Ubuntu 14.04 LTS
    config.vm.box = "ubuntu/trusty64"
    # XXX: for remote work, otherwise it causes slow HTTP timeout
    config.vm.box_check_update = false
    config.vm.network "public_network", auto_config: false, :nictype => "82545EM"
    #config.vm.network "private_network", ip: "10.0.2.215", auto_config: false, :nictype => "82545EM"
    
    #config.vm.synced_folder ".", "/vagrant"
    config.vm.provision :shell, inline: "cd /vagrant; scripts/setup-vagrant.bash", :privileged => false
    config.vm.provision :unix_reboot
    # XXX: DPDK is kernel specific, and setup-vagrant upgrades the kernel
    config.vm.provision :shell, inline: "cd /vagrant; scripts/setup-dpdk.bash", :privileged => false
    config.vm.provision :shell, run: "always", inline: "cd /vagrant; scripts/configure-vagrant.bash", :privileged => true
end

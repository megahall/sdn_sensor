VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
    # Ubuntu 14.04 LTS
    config.vm.box = "ubuntu/trusty64"
    # XXX: for remote work, otherwise it causes slow HTTP timeout
    config.vm.box_check_update = false
    config.vm.network "public_network", auto_config: false, :nictype => "virtio"
    #config.vm.network "private_network", ip: "10.0.2.215", auto_config: false, :nictype => "virtio"

    #config.vm.provision :shell, path: 'scripts/setup-vagrant.bash', :privileged => false

    config.vm.provider "virtualbox" do |vb|
        #vb.gui = true
        vb.customize ["modifyvm", :id, "--memory", "2048"]
        vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
        vb.customize ["modifyvm", :id, "--natdnsproxy1", "on"]
        vb.customize ["modifyvm", :id, "--nictype1", "virtio"]
        vb.customize ["modifyvm", :id, "--nictype2", "virtio"]
        vb.customize ["setextradata", :id, "VBoxInternal/CPUM/SSE4.1", "1"]
        vb.customize ["setextradata", :id, "VBoxInternal/CPUM/SSE4.2", "1"]
    end
end

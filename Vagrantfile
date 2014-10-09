VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
    config.vm.define "sensor" do |sensor|
        # Ubuntu 14.04 LTS
        sensor.vm.box = "hashicorp/trusty64"
        sensor.vm.network "private_network", ip: "10.210.210.100"
        sensor.vm.network :bridged, { "nic_type": "virtio" }
        sensor.vm.provision :shell, inline: 'echo sdn_sensor > /etc/hostname; echo "127.0.0.1 sdn_sensor" >> /etc/hosts; hostname sdn_sensor'
        #sensor.vm.provision :shell, path: 'setup-vagrant.bash'
    end
    config.vm.provider "virtualbox" do |vb|
        vb.customize ["modifyvm", :id, "--memory", "2048"]
        vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
        vb.customize ["modifyvm", :id, "--natdnsproxy1", "on"]
        vb.customize ["modifyvm", :id, "--nictype1", "virtio"]
    end
end

default:
    just --list

push:
    sudo chown root config.json
    sudo chown root ACL.json

    sudo cp ./config.json /root/.config/heretek/config.json
    sudo cp ./ACL.json /root/.config/heretek/ACL.json

    sudo rm ./config.json
    sudo rm ./ACL.json

pull:
    sudo cp /root/.config/heretek/config.json ./
    sudo cp /root/.config/heretek/ACL.json ./

    sudo chown aknen config.json
    sudo chown aknen ACL.json

install:
    sudo ./target/debug/htek bringdown
    cargo build
    sudo cp ./target/debug/htek /usr/bin/htek

restart:
    sudo htek bringdown
    sleep 2
    sudo htek bringup

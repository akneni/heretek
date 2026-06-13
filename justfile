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
    sudo ./target/debug/htek down
    cargo build
    sudo cp ./target/debug/htek /usr/bin/htek

reinstall:
    sudo ./target/debug/htek down
    cargo build
    sudo cp ./target/debug/htek /usr/bin/htek
    sudo htek up

restart:
    sudo htek down
    sudo htek up

start_sync:
    sudo htek down
    cargo build
    pixi run load
    sudo ./target/debug/htek daemon

start_syncr:
    sudo htek down
    cargo build --release
    pixi run load
    sudo ./target/release/htek daemon

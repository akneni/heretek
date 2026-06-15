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
    cargo build --workspace
    sudo cp ./target/debug/htek /usr/bin/htek
    sudo cp ./target/debug/htekd /usr/bin/htekd

reinstall:
    sudo ./target/debug/htek down
    cargo build --workspace
    sudo cp ./target/debug/htek /usr/bin/htek
    sudo cp ./target/debug/htekd /usr/bin/htekd
    sudo htek up

restart:
    sudo htek down
    sudo htek up

start_sync:
    sudo htek down
    cargo build --workspace
    pixi run --manifest-path htek_daemon/pixi.toml load
    sudo ./target/debug/htekd

start_syncr:
    sudo htek down
    cargo build --workspace --release
    pixi run --manifest-path htek_daemon/pixi.toml load
    sudo ./target/release/htekd

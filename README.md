# Readme

To build, first install go-yara.

1. Download the source package of yara from here: https://github.com/VirusTotal/yara/releases. Tested with yara-4.22
2. Extract into a folder, e.g. `yara-4.22`
3. Get go-yara v4 with `go get github.com/hillu/go-yara/v4`
4. You might need libssl installed: `sudo apt-get install libssl-dev`
5. Install go-yara with the yara source files:

    ```
    export CGO_CFLAGS="-Iyara-4.2.2/libyara/include"
    export CGO_LDFLAGS="-Lyara-4.2.2/libyara/.libs -lyara"
    go install -tags yara_no_pkg_config github.com/hillu/go-yara/v4
    ```

After this hopefully the application should be installable/runnable as normal.

This has worked too: `export CGO_LDFLAGS="-static $(pkg-config --static --libs yara)"` - after installing yara, that embedded command returns `-L/usr/local/lib -lyara -lm`

For uploading to lambda manually, a command like `rm main.zip; go build -o main && zip main.zip main` can be helpful.
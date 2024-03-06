import subprocess


def install_gophish():
    try:
        print("Installing prerequisites...")
        subprocess.run(["sudo", "apt", "update", "-y"], check=True)
        subprocess.run(["sudo", "apt", "upgrade", "-y"], check=True)
        subprocess.run(["sudo", "apt", "update", "-y"], check=True)

        print("Installing go...")
        subprocess.run(
            ["wget", "https://go.dev/dl/go1.22.0.linux-amd64.tar.gz"], check=True)
        subprocess.run(["sudo", "su"], check=True)
        subprocess.run(["rm", "-rf", "/usr/local/go", "&&", "tar", "-C",
                       "/usr/local", "-xzf", "go1.22.0.linux-amd64.tar.gz"], check=True)
        subprocess.run(["exit"], check=True)
        subprocess.run(["export", "PATH=$PATH:/usr/local/go/bin"], check=True)
        subprocess.run(["go", "version"], check=True)

        print("Installing gophish...")
        subprocess.run(
            ["mkdir", "Gophish"], check=True)
        subprocess.run(
            ["cd", "Gophish"], check=True)
        subprocess.run(
            ["wget", "https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip"], check=True)
        subprocess.run(["sudo", "apt", "install", "unzip"], check=True)
        subprocess.run(
            ["unzip", "gophish-v0.12.1-linux-64bit.zip"], check=True)
        subprocess.run(
            ["rm", "config.json"], check=True)
        subprocess.run(
            ["wget", "http://103.127.134.192:9999/config.json"], check=True)
        subprocess.run(
            ["chmod", "+x", "gophish"], check=True)

        print("Installing webhooks...")
        subprocess.run(
            ["git", "clone", "https://github.com/gophish/webhook.git"], check=True)

        print("Next Step:")
        print("1. Run Gophish -> sudo ./gophish")
        print("2. Run webhook -> go run webhook -h 0.0.0.0 -p 9999")

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    install_gophish()

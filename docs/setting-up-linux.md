# Installing Guard \(Linux, macOS, or Unix\)<a name="setting-up-linux"></a>

On a Linux, macOs, or Unix environment, you can install AWS CloudFormation Guard by using either the pre\-built release binary or Cargo, which is the Rust package manager\.

## To install Guard from a pre\-built release binary<a name="install-pre-built-binaries"></a>

Use the following procedure to install Guard from a pre\-built binary\.

1. Open a terminal, and run the following command\.

   ```
   curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/aws-cloudformation/cloudformation-guard/main/install-guard.sh | sh
   ```

1. Run the following command to set your `PATH` variable\.

   ```
   PATH=~/.guard/bin/
   ```

   *Results:* You have successfully installed Guard and set the `PATH` variable\.

   1. \(Optional\) To confirm the installation of Guard, run the following command\.

     ```
     cfn-guard --version
     ```

     The command returns the following output\.

     ```
     cfn-guard 2.0
     ```

## To install the Rust package manager<a name="install-rust-and-cargo"></a>

Cargo is the Rust package manager\. Complete the following steps to install Rust which includes Cargo\.

1. Run the following command from a terminal, and follow the onscreen instructions to install Rust\.

   ```
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

   1. \(Optional\) For Ubuntu environments, run the following command\.

     ```
     sudo apt-get update; sudo apt install build-essential
     ```

1. Configure your `PATH` environment variable, and run the following command\.

   ```
   source $HOME/.cargo/env
   ```

## To install Guard from Cargo<a name="install-guard-rust-and-cargo-linux"></a>

Open a terminal, and run the following command\.

```
cargo install cfn-guard
```

*Results*: You have successfully installed Guard\.

\(Optional\) To confirm the installation of Guard, run the following command\.

```
cfn-guard --version
```

The command returns the following output\.

```
cfn-guard 2.0
```
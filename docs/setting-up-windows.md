# Installing Guard \(Windows\)<a name="setting-up-windows"></a>

On a Windows host, you can install AWS CloudFormation Guard by using Cargo, the Rust package manager\. 

## Prerequisites<a name="w15aac10c11c16b5"></a>

Complete these prerequisites before you install Guard on your Windows host:
+ [Install Microsoft Visual C\+\+ Build Tools](#install-build-tools)
+ [To install Rust package manager](#install-rust-package-manager)
+ [To install Guard from Cargo](#install-guard-rust-and-cargo)

## Install Microsoft Visual C\+\+ Build Tools<a name="install-build-tools"></a>

To build Guard from the command line interface, you must install the Build Tools for Visual Studio 2019\.

1. Download Microsoft Visual C\+\+ build tools from the [Build Tools for Visual Studio 2019](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2019) website\.

1. Run the installer, and select the defaults\.

## To install Rust package manager<a name="install-rust-package-manager"></a>

Download and install Rust, which contains the package manager Cargo\.

1. [Download Rust](https://forge.rust-lang.org/infra/other-installation-methods.html#other-ways-to-install-rustup) and then run **rustup\-init\.exe**\.

1. From the command prompt, choose **1**, which is the default option\.

   The command returns the following output\.

   ```
   Rust is installed now. Great!
       
       To get started you may need to restart your current shell.
       This would reload its PATH environment variable to include
       Cargo's bin directory (%USERPROFILE%\.cargo\bin).
       
       Press the Enter key to continue.
   ```

1. To finish the installation, press the **Enter** key\.

## To install Guard from Cargo<a name="install-guard-rust-and-cargo"></a>

Open a terminal, and then run the following command\.

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
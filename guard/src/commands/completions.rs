use crate::{commands::CfnGuard, rules};
use clap::{Args, CommandFactory, ValueEnum};

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl From<String> for Shell {
    fn from(value: String) -> Self {
        match value.as_str() {
            "bash" => Shell::Bash,
            "zsh" => Shell::Zsh,
            "fish" => Shell::Fish,
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, Args)]
pub struct Completions {
    #[arg(short, long, value_enum)]
    shell: Shell,
}

impl Completions {
    pub fn execute(&self) -> rules::Result<i32> {
        let mut app = CfnGuard::command();
        match &self.shell {
            Shell::Bash => generate(clap_complete::shells::Bash, &mut app),
            Shell::Zsh => generate(clap_complete::shells::Zsh, &mut app),
            Shell::Fish => generate(clap_complete::shells::Fish, &mut app),
        }

        Ok(0)
    }
}

fn generate<G: clap_complete::Generator>(gen: G, cmd: &mut clap::Command) {
    clap_complete::generate(gen, cmd, cmd.get_name().to_string(), &mut std::io::stdout());
}

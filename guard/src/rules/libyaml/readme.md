Note: This package contains code that is copied over from [serde_yaml](https://github.com/dtolnay/serde-yaml). Credit to [David Tolnay](https://github.com/dtolnay) for its implementation.
We couldn't directly depend on serde_yaml since the customizations we needed were to libyaml package used by the dependent repo which couldn't be exported as it's not made public. 

Please keep an eye out for any possible issues raised in serde_yaml. 
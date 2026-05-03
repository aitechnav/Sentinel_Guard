"""Setup with post-install hook to download spaCy model for Presidio PII detection."""

import subprocess
import sys
from setuptools import setup
from setuptools.command.install import install


class PostInstallCommand(install):
    """Post-installation: download spaCy model required by Presidio."""

    def run(self):
        install.run(self)
        self._download_spacy_model()

    def _download_spacy_model(self):
        model = "en_core_web_lg"
        print(f"🔍 Checking spaCy model: {model}")
        try:
            import spacy
            try:
                spacy.load(model)
                print(f"✅ {model} — already installed")
            except OSError:
                print(f"⬇️  {model} — downloading...")
                subprocess.check_call(
                    [sys.executable, "-m", "spacy", "download", model]
                )
                print(f"✅ {model} — installed")
        except ImportError:
            print("⚠️  spaCy not installed, skipping model download")
        except Exception as e:
            print(f"⚠️  Could not download {model}: {e}")
            print(f"   Run manually: python -m spacy download {model}")


if __name__ == "__main__":
    setup(
        cmdclass={
            "install": PostInstallCommand,
        },
    )

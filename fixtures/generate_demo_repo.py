import os
import subprocess
import shutil

def run_cmd(args, cwd):
    subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

def generate_repo(target_dir):
    # Clean up existing dir if it exists
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir)
    os.makedirs(target_dir, exist_ok=True)
    
    # Initialize Git repository
    run_cmd(["git", "init"], target_dir)
    # Configure user for commits
    run_cmd(["git", "config", "user.name", "Security Inspector"], target_dir)
    run_cmd(["git", "config", "user.email", "inspector@secrettrace.ai"], target_dir)
    
    # Commit 1: Project init and some safe config
    with open(os.path.join(target_dir, "app_config.py"), "w") as f:
        f.write("# SecretTrace Demo Config\n")
        f.write("DEBUG = True\n")
        f.write("PORT = 8080\n")
        
    run_cmd(["git", "add", "app_config.py"], target_dir)
    run_cmd(["git", "commit", "-m", "Initial commit: setup app configurations"], target_dir)
    
    # Commit 2: Introduce a realistic Stripe secret key
    mock_stripe_key = "sk_live_" + "51N2xabcdefghijklmnopqrstuvw"
    with open(os.path.join(target_dir, "app_config.py"), "w") as f:
        f.write("# SecretTrace Demo Config\n")
        f.write("DEBUG = True\n")
        f.write("PORT = 8080\n")
        f.write(f"STRIPE_SECRET_KEY = \"{mock_stripe_key}\"\n")
        
    run_cmd(["git", "add", "app_config.py"], target_dir)
    run_cmd(["git", "commit", "-m", "Integrate Stripe billing payment gateway"], target_dir)
    
    # Commit 3: Add a placeholder API key and variable
    with open(os.path.join(target_dir, "app_config.py"), "w") as f:
        f.write("# SecretTrace Demo Config\n")
        f.write("DEBUG = True\n")
        f.write("PORT = 8080\n")
        f.write(f"STRIPE_SECRET_KEY = \"{mock_stripe_key}\"\n")
        f.write("AWS_ACCESS_KEY_ID = \"YOUR_AWS_ACCESS_KEY_ID_HERE\"\n")
        f.write("AWS_SECRET_ACCESS_KEY = \"your-aws-secret-access-key-goes-here\"\n")
        
    run_cmd(["git", "add", "app_config.py"], target_dir)
    run_cmd(["git", "commit", "-m", "Add placeholder variables for AWS S3 upload config"], target_dir)
    
    # Commit 4: Delete the Stripe secret key (Oops! Deleted, but stays in git log)
    with open(os.path.join(target_dir, "app_config.py"), "w") as f:
        f.write("# SecretTrace Demo Config\n")
        f.write("DEBUG = True\n")
        f.write("PORT = 8080\n")
        f.write("AWS_ACCESS_KEY_ID = \"YOUR_AWS_ACCESS_KEY_ID_HERE\"\n")
        f.write("AWS_SECRET_ACCESS_KEY = \"your-aws-secret-access-key-goes-here\"\n")
        
    run_cmd(["git", "add", "app_config.py"], target_dir)
    run_cmd(["git", "commit", "-m", "Remove plaintext Stripe key, migrate to environment variables"], target_dir)
    
    # Commit 5: Add a test fixture token in a test file
    os.makedirs(os.path.join(target_dir, "tests", "fixtures"), exist_ok=True)
    with open(os.path.join(target_dir, "tests", "fixtures", "credentials.json"), "w") as f:
        f.write("{\n")
        f.write("  \"stripe_test_key\": \"sk_test_51N2xabcdefghijklmnopqrstuvw\",\n")
        f.write("  \"dummy_token\": \"ghp_dummytoken1234567890abcdefghijklmn\"\n")
        f.write("}\n")
        
    run_cmd(["git", "add", "tests/fixtures/credentials.json"], target_dir)
    run_cmd(["git", "commit", "-m", "Add mock fixtures for integration tests"], target_dir)
    
    # Commit 6: Add documentation with an example credentials structure
    os.makedirs(os.path.join(target_dir, "docs"), exist_ok=True)
    with open(os.path.join(target_dir, "docs", "setup.md"), "w") as f:
        f.write("# Developer Setup Guide\n\n")
        f.write("To configure the application, configure your credentials like so:\n")
        f.write("```bash\n")
        f.write("export OPENAI_API_KEY=\"sk-example1234567890abcdefghijklmnopqrstuvwxyz12\"\n")
        f.write("```\n")
        
    run_cmd(["git", "add", "docs/setup.md"], target_dir)
    run_cmd(["git", "commit", "-m", "Create setup guide documentation with example variables"], target_dir)
    
    print(f"[+] Successfully generated demo Git repository at {target_dir}")

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "fixtures/demo_repo"
    generate_repo(target)

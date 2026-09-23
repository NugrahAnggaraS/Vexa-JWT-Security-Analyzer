"""Allow ``python -m jwt_analyzer`` to run the same CLI as the ``vexa`` command."""

from jwt_analyzer.main import main

if __name__ == "__main__":
    main()

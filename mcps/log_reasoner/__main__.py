import argparse
import json

from backend.mcps.log_reasoner.run import run


def main() -> None:
    parser = argparse.ArgumentParser(description="Run LogReasoner MCP")
    parser.add_argument("--log", required=True, help="Path to log file")
    parser.add_argument("--context", default="{}", help="Context JSON string")
    args = parser.parse_args()

    try:
        context = json.loads(args.context)
    except json.JSONDecodeError:
        context = {}

    result = run(log_path=args.log, context=context)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

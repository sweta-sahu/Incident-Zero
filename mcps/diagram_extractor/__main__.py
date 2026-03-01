import argparse
import json

from backend.mcps.diagram_extractor.run import run


def main() -> None:
    parser = argparse.ArgumentParser(description="Run DiagramExtractor MCP")
    parser.add_argument("--image", required=True, help="Path to diagram image")
    parser.add_argument("--context", default="{}", help="Context JSON string")
    args = parser.parse_args()

    try:
        context = json.loads(args.context)
    except json.JSONDecodeError:
        context = {}

    result = run(image_path=args.image, context=context)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

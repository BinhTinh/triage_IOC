#!/usr/bin/env python3

import asyncio
import argparse
import sys
from pathlib import Path
from datetime import datetime

from src.core.analysis_pipeline import run_ioc_extraction
from src.config.settings import settings


def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     VOLATILITY3 IOC EXTRACTION SYSTEM                         ║
║                        Memory Forensics Automation                            ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)


async def analyze_command(args):
    print_banner()
    
    dump_path = args.dump
    if not Path(dump_path).exists():
        print(f"Error: File not found: {dump_path}")
        sys.exit(1)
    
    goal = args.goal
    output_dir = args.output or settings.reports_dir
    
    print(f"Dump Path: {dump_path}")
    print(f"Analysis Goal: {goal}")
    print(f"Output Directory: {output_dir}")
    print("="*80)
    print()
    
    try:
        result = await run_ioc_extraction(dump_path, goal, output_dir)
        
        print()
        print("="*80)
        print("ANALYSIS RESULTS")
        print("="*80)
        print(f"Case ID:        {result['case_id']}")
        print(f"Status:         {result['status']}")
        print(f"Threat Level:   {result['threat_level']}")
        print(f"Threat Score:   {result['threat_score']}/100")
        print(f"Total IOCs:     {result['summary']['total_iocs']}")
        print(f"Malicious:      {result['summary']['malicious']}")
        print(f"Suspicious:     {result['summary']['suspicious']}")
        print()
        print(f"Report Directory: {result['report_directory']}")
        print()
        print("Top Recommendations:")
        for i, rec in enumerate(result.get('top_recommendations', [])[:5], 1):
            print(f"  {i}. {rec}")
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error during analysis: {e}")
        sys.exit(1)


async def server_command(args):
    from src.mcp_server.server import run_server
    
    print_banner()
    print(f"Starting MCP Server...")
    print(f"Transport: {args.transport}")
    
    if args.transport in ["http", "sse"]:
        print(f"Host: {args.host}")
        print(f"Port: {args.port}")
    
    run_server(args.transport, args.host, args.port)


def main():
    parser = argparse.ArgumentParser(
        description="Volatility3 IOC Extraction System",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a memory dump")
    analyze_parser.add_argument("dump", help="Path to memory dump file")
    analyze_parser.add_argument(
        "--goal", "-g",
        choices=["malware_detection", "incident_response", "quick_triage", "rootkit_hunt"],
        default="malware_detection",
        help="Analysis goal (default: malware_detection)"
    )
    analyze_parser.add_argument(
        "--output", "-o",
        help="Output directory for reports"
    )
    
    server_parser = subparsers.add_parser("server", help="Start MCP server")
    server_parser.add_argument(
        "--transport", "-t",
        choices=["stdio", "http", "sse"],
        default="stdio",
        help="Transport protocol (default: stdio)"
    )
    server_parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind (default: 0.0.0.0)"
    )
    server_parser.add_argument(
        "--port", "-p",
        type=int,
        default=8000,
        help="Port to bind (default: 8000)"
    )
    
    args = parser.parse_args()
    
    if args.command == "analyze":
        asyncio.run(analyze_command(args))
    elif args.command == "server":
        asyncio.run(server_command(args))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
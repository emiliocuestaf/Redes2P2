import argparse

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(help='types of A')

parser.add_argument("-t",
                    choices = ["A", "B"],
                    dest = "type",
                    required=True,
                    action='store',
                    help="Some help blah blah")

cam_parser = subparsers.add_parser('a1', help='Default')
cam_parser.set_defaults(which='a1')

cam_parser = subparsers.add_parser('a2', help='parse this instead of default')
cam_parser.set_defaults(which='a2')


parser.add_argument("-v",
                    nargs = '+',
                    required=True,
                    dest = "version",
                    type=int,
                    action='store',
                    help="some version help blah blah")   

argument = parser.parse_args()

print argument.type
print argument.version
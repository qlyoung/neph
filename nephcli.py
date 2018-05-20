from prompt_toolkit import prompt

class NephCLI(object):
    def __init__(self, commands=None, prompt=">>"):
        self.commands = {} if commands is None else commands
        self.prompt = prompt

    def add_cmd(self, cmd, handler):
        self.commands[cmd] = handler

    def show_help(self):
        print("Available commands:")
        print(list(self.commands.keys()))

    def repl(self):
        cmd = None
        while (cmd != "exit"):
            cmd = prompt(self.prompt + " ")
            if cmd == "help":
                self.show_help()
                continue
            if cmd == '':
                continue
            if cmd == '' or cmd not in self.commands:
                print("[!] No such command")
                continue
            
            self.commands[cmd](cmd)


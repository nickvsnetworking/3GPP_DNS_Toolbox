project('myproject', 'c')

# Source files
src_dir = 'src'
sources = ['main.c', 'dns_resolvers.c', 'naptr.c', 'regex_extensions.c']
sources = [join_paths(src_dir, s) for s in sources]

# Compiler options
cc = meson.get_compiler('c')
c_args = ['-Wall', '-Wextra']

# Build target
executable('myprogram', sources, c_args: c_args)

# if i make a change, sometimes these dont get recompiled so it's nice to just remove
# them all and force it to recompile them.
find ./ -iname *.pyc -exec rm -f '{}' ';'

#!/bin/bash

rm -rf ./docs/
pdoc3 --html -o ./docs/ litestar_sso
mv ./docs/litestar_sso/* ./docs/
rm -rf ./docs/litestar_sso

from __future__ import print_function
import sys
from jinja2 import Environment, contextfilter, Template
from markupsafe import Markup


def jinja2_env(*args, **kwargs):
    """Create jinja2 environment"""
    return Environment(*args, **kwargs)

@contextfilter
def render(context, value, envoptions=None, **vars):
    """Render value as jinja template with provided variables"""
    # print("VALUE: %s OPTIONS %s CONTEXT %s VARS %s" % (value, envoptions, context.get_all().keys(), context.vars.keys()), file=sys.stderr)

    if envoptions is None:
        envoptions = {}
    env = Environment(**envoptions)
    tmpl = env.from_string(value)

    if not vars:
        local_vars = context.get_all()
    else:
        local_vars = {}
        local_vars.update(context.get_all())
        local_vars.update(vars)

    result = tmpl.render(local_vars)
    #result = Template(value).render(context)
    if context.eval_ctx.autoescape:
        result = Markup(result)
    return result


class FilterModule(object):
    ''' Custom filters are loaded by FilterModule objects '''

    def filters(self):
        ''' FilterModule objects return a dict mapping filter names to
            filter functions. '''
        return {
            'render': render,
            'jinja2_env': jinja2_env
        }

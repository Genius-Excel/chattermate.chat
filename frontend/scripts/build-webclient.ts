import { build } from 'esbuild'
import { resolve, dirname } from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

async function buildWebClient() {
  try {
    await build({
      entryPoints: [resolve(dirname(__dirname), 'src/webclient/chattermate.js')],
      bundle: true,
      minify: true,
      outfile: resolve(dirname(__dirname), 'public/webclient/chattermate.min.js'),
      format: 'iife',
      target: ['es2015'],
      loader: {
        '.svg': 'text',
      },
    })

    console.log('Web client built successfully!')
  } catch (error) {
    console.error('Build failed:', error)
    process.exit(1)
  }
}

buildWebClient()

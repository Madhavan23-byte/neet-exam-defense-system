import asyncio
import asyncpg

async def check():
    conn = await asyncpg.connect('postgresql://postgres:root@localhost:5432/bsea')
    tables = await conn.fetch("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
    print('Current public tables in bsea:', [t[0] for t in tables])
    print('Total public tables count:', len(tables))
    await conn.close()

if __name__ == '__main__':
    asyncio.run(check())

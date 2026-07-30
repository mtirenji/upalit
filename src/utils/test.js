import dotenv from 'dotenv';
import { withDb, getDb } from '../db.js';

dotenv.config();

const test = async () => {
  console.log('🧪 Running database test...\n');

  try {
    await withDb();
    const db = getDb();

    console.log('✅ Database connected');
    console.log(`📊 Users: ${db.users.length}`);
    console.log(`📊 Properties: ${db.properties.length}`);
    console.log(`📊 Tokens: ${db.tokens.length}`);
    console.log(`📊 Audit Log: ${db.auditLog.length}`);

    if (db.users.length > 0) {
      console.log('\n👤 Sample Users:');
      db.users.slice(0, 3).forEach(user => {
        console.log(`  - ${user.fullName} (${user.email}) [${user.role}]`);
      });
    }

    if (db.properties.length > 0) {
      console.log('\n🏠 Sample Properties:');
      db.properties.slice(0, 3).forEach(prop => {
        console.log(`  - ${prop.name} (${prop.location}) [${prop.status}]`);
      });
    }

    console.log('\n✅ Test completed successfully!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Test failed:', error);
    process.exit(1);
  }
};

test();
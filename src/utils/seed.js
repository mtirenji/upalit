import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import { withDb, getDb, save, generateId } from '../db.js';

dotenv.config();

const log = (message, type = 'info') => {
  const prefix = { info: 'ℹ️', success: '✅', error: '❌', warn: '⚠️' }[type] || 'ℹ️';
  console.log(`${prefix} ${message}`);
};

const seed = async () => {
  log('Starting database seed...', 'info');

  try {
    await withDb();
    const db = getDb();

    // ===== Admin User =====
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@upalit.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123!';
    const adminFullName = process.env.ADMIN_NAME || 'System Administrator';

    const existingAdmin = db.users.find(u => u.email.toLowerCase() === adminEmail.toLowerCase());

    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash(adminPassword, 12);
      db.users.push({
        id: generateId(),
        email: adminEmail.toLowerCase(),
        fullName: adminFullName,
        password: hashedPassword,
        role: 'admin',
        kycStatus: 'verified',
        disabled: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
      log(`Admin created: ${adminEmail}`, 'success');
    } else {
      log(`Admin already exists: ${adminEmail}`, 'info');
    }

    // ===== Sample Users =====
    if (db.users.filter(u => u.role === 'investor').length < 3) {
      const sampleUsers = [
        { fullName: 'John Doe', email: 'john@example.com', password: 'Password123!', kycStatus: 'verified' },
        { fullName: 'Jane Smith', email: 'jane@example.com', password: 'Password123!', kycStatus: 'pending' },
        { fullName: 'Bob Johnson', email: 'bob@example.com', password: 'Password123!', kycStatus: 'rejected' },
      ];

      for (const userData of sampleUsers) {
        if (!db.users.find(u => u.email === userData.email)) {
          const hashedPassword = await bcrypt.hash(userData.password, 12);
          db.users.push({
            id: generateId(),
            email: userData.email,
            fullName: userData.fullName,
            password: hashedPassword,
            role: 'investor',
            kycStatus: userData.kycStatus,
            disabled: false,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          });
          log(`Sample user created: ${userData.email}`, 'success');
        }
      }
    }

    // ===== Sample Properties =====
    if (db.properties.length === 0) {
      const sampleProperties = [
        { name: 'Marina Court, Unit 14B', location: 'Dubai Marina', description: 'Luxury 2-bedroom apartment with panoramic sea views.', price: 2150000, tokenPrice: 215, totalTokens: 10000, tokensSold: 6200, status: 'active', lastAppraisal: '2026-05-15T00:00:00.000Z' },
        { name: 'Circle Residence, 3-Bed Villa', location: 'Jumeirah Village Circle', description: 'Spacious 3-bedroom villa with private garden and pool.', price: 2740500, tokenPrice: 189, totalTokens: 14500, tokensSold: 5945, status: 'active', lastAppraisal: '2026-04-20T00:00:00.000Z' },
        { name: 'Bay Terraces, Unit 9C', location: 'Business Bay', description: 'Modern 1-bedroom apartment in the heart of Dubai\'s business district.', price: 1976200, tokenPrice: 241, totalTokens: 8200, tokensSold: 7216, status: 'active', lastAppraisal: '2026-06-01T00:00:00.000Z' },
        { name: 'Palm View Residences, Penthouse', location: 'Palm Jumeirah', description: 'Exclusive penthouse with direct views of the Arabian Gulf.', price: 5500000, tokenPrice: 550, totalTokens: 10000, tokensSold: 0, status: 'draft', lastAppraisal: '2026-06-10T00:00:00.000Z' },
      ];

      const admin = db.users.find(u => u.role === 'admin');
      for (const propData of sampleProperties) {
        db.properties.push({
          id: generateId(),
          ...propData,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          createdBy: admin?.id || null,
        });
        log(`Property created: ${propData.name}`, 'success');
      }
    }

    // ===== Sample Tokens =====
    if (db.tokens.length === 0 && db.users.length > 0 && db.properties.length > 0) {
      const investor = db.users.find(u => u.role === 'investor');
      const property = db.properties.find(p => p.status === 'active');

      if (investor && property) {
        db.tokens.push({
          id: generateId(),
          userId: investor.id,
          propertyId: property.id,
          quantity: Math.floor(Math.random() * 100) + 10,
          averagePrice: property.tokenPrice * (0.95 + Math.random() * 0.1),
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        });
        log(`Sample token holdings created for ${investor.email}`, 'success');
      }
    }

    // ===== Sample Audit Log =====
    if (db.auditLog.length < 5) {
      const admin = db.users.find(u => u.role === 'admin');
      if (admin) {
        const sampleActions = [
          { action: 'kyc_update', targetUserId: db.users.find(u => u.role === 'investor')?.id, details: { status: 'verified' } },
          { action: 'property_created', targetPropertyId: db.properties[0]?.id, details: { name: db.properties[0]?.name } },
        ];

        for (const actionData of sampleActions) {
          db.auditLog.push({
            id: generateId(),
            userId: admin.id,
            action: actionData.action,
            targetUserId: actionData.targetUserId || null,
            targetPropertyId: actionData.targetPropertyId || null,
            oldValue: null,
            newValue: null,
            reason: 'Seed data',
            details: actionData.details,
            timestamp: new Date().toISOString(),
          });
        }
        log('Sample audit log entries created', 'success');
      }
    }

    await save();

    console.log('\n📊 Database Summary:');
    console.log(`  Users: ${db.users.length}`);
    console.log(`  Properties: ${db.properties.length}`);
    console.log(`  Tokens: ${db.tokens.length}`);
    console.log(`  Audit Log: ${db.auditLog.length}`);
    console.log('\n🔐 Admin Credentials:');
    console.log(`  Email: ${process.env.ADMIN_EMAIL || 'admin@upalit.com'}`);
    console.log(`  Password: ${process.env.ADMIN_PASSWORD || 'Admin123!'}`);
    console.log('\n⚠️  Please change the admin password after first login!');

    process.exit(0);
  } catch (error) {
    console.error('❌ Seed failed:', error);
    process.exit(1);
  }
};

seed();
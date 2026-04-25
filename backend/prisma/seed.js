const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function main() {
  try {
    // Clear existing data
    console.log('Clearing existing data...');
    await prisma.message.deleteMany();
    await prisma.overtimeRequest.deleteMany();
    await prisma.productionRecord.deleteMany();
    await prisma.CCTV.deleteMany();
    await prisma.floor.deleteMany();
    await prisma.graphData.deleteMany();
    await prisma.report.deleteMany();
    await prisma.user.deleteMany();

    // Hash password
    const hashedPassword = await bcrypt.hash('admin1234', 10);

    // Create Floors FIRST (before creating users with floor assignments)
    console.log('Creating floors...');
    const floors = [];
    const floorData = [
      { name: 'Ground Floor', level: 0, area: 5000 },
      { name: '1st Floor', level: 1, area: 4500 },
      { name: '2nd Floor', level: 2, area: 4500 },
      { name: '3rd Floor', level: 3, area: 4500 },
      { name: '4th Floor', level: 4, area: 4500 },
      { name: '5th Floor', level: 5, area: 4500 },
      { name: '6th Floor', level: 6, area: 4500 },
      { name: '7th Floor', level: 7, area: 4500 }
    ];

    for (const data of floorData) {
      const floor = await prisma.floor.create({
        data: {
          name: data.name,
          level: data.level,
          area: data.area,
          status: 'active'
        }
      });
      floors.push(floor);
    }

    const [floor1, floor2, floor3, floor4, floor5, floor6, floor7, floor8] = floors;

    // Create Users
    console.log('Creating users...');
    const adminUser = await prisma.user.create({
      data: {
        name: 'Admin User',
        email: 'admin@motionmatrix.com',
        password: hashedPassword,
        role: 'ADMIN',
        department: 'Administration',
        phone: '1234567890',
        nid: 'NID001',
        gender: 'Male',
        joinDate: new Date('2025-01-01'),
        position: 'Administrator'
      }
    });

    const ownerUser = await prisma.user.create({
      data: {
        name: 'Owner Admin',
        email: 'owner@motionmatrix.com',
        password: hashedPassword,
        role: 'OWNER',
        department: 'Executive',
        phone: '0987654321',
        nid: 'NID002',
        gender: 'Female',
        joinDate: new Date('2024-01-01'),
        position: 'Owner'
      }
    });

    // Create 8 Floor Managers - one for each floor
    console.log('Creating floor managers...');
    const floorManagers = [];
    const floorManagerData = [
      { name: 'Ahmed Hassan', email: 'ahmed.hassan@company.com', department: 'Sewing', phone: '1111111111', nid: 'NID003', gender: 'Male' },
      { name: 'Fatima Khan', email: 'fatima.khan@company.com', department: 'Cutting', phone: '2222222222', nid: 'NID004', gender: 'Female' },
      { name: 'Mohammad Ali', email: 'mohammad.ali@company.com', department: 'Sewing', phone: '3333333333', nid: 'NID005', gender: 'Male' },
      { name: 'Zainab Ahmed', email: 'zainab.ahmed@company.com', department: 'Stitching', phone: '4444444444', nid: 'NID006', gender: 'Female' },
      { name: 'Hassan Ibrahim', email: 'hassan.ibrahim@company.com', department: 'Pressing', phone: '5555555555', nid: 'NID007', gender: 'Male' },
      { name: 'Layla Mohamed', email: 'layla.mohamed@company.com', department: 'Quality', phone: '6666666666', nid: 'NID008', gender: 'Female' },
      { name: 'Karim Saleh', email: 'karim.saleh@company.com', department: 'Packing', phone: '7777777777', nid: 'NID009', gender: 'Male' },
      { name: 'Amira Hassan', email: 'amira.hassan@company.com', department: 'Finishing', phone: '8888888888', nid: 'NID010', gender: 'Female' }
    ];

    for (let i = 0; i < floorManagerData.length; i++) {
      const manager = await prisma.user.create({
        data: {
          name: floorManagerData[i].name,
          email: floorManagerData[i].email,
          password: hashedPassword,
          role: 'FLOOR_MANAGER',
          department: floorManagerData[i].department,
          workerId: `FM00${i + 1}`,
          phone: floorManagerData[i].phone,
          nid: floorManagerData[i].nid,
          gender: floorManagerData[i].gender,
          joinDate: new Date('2025-02-01'),
          position: 'Floor Manager',
          assignedFloorId: floors[i].id
        }
      });
      floorManagers.push(manager);
    }

    // Create Workers - some assigned to floors, some unassigned
    console.log('Creating workers...');
    const workers = [];
    const workerNames = [
      { name: 'Ali Worker', email: 'ali.worker@company.com', dept: 'Sewing', phone: '1001001001', nid: 'NID011' },
      { name: 'Noor Worker', email: 'noor.worker@company.com', dept: 'Cutting', phone: '1002002002', nid: 'NID012' },
      { name: 'Sara Ahmad', email: 'sara.ahmad@company.com', dept: 'Stitching', phone: '1003003003', nid: 'NID013' },
      { name: 'Omar Hassan', email: 'omar.hassan@company.com', dept: 'Sewing', phone: '1004004004', nid: 'NID014' },
      { name: 'Hana Ali', email: 'hana.ali@company.com', dept: 'Pressing', phone: '1005005005', nid: 'NID015' },
      { name: 'Rashid Mohamed', email: 'rashid.mohamed@company.com', dept: 'Quality', phone: '1006006006', nid: 'NID016' },
      { name: 'Leila Ahmed', email: 'leila.ahmed@company.com', dept: 'Packing', phone: '1007007007', nid: 'NID017' },
      { name: 'Youssef Ibrahim', email: 'youssef.ibrahim@company.com', dept: 'Finishing', phone: '1008008008', nid: 'NID018' },
      { name: 'Maryam Hassan', email: 'maryam.hassan@company.com', dept: 'Sewing', phone: '1009009009', nid: 'NID019' },
      { name: 'Khalid Ahmed', email: 'khalid.ahmed@company.com', dept: 'Cutting', phone: '1010010010', nid: 'NID020' }
    ];

    // Create workers: first 5 will be assigned to different floors, last 5 unassigned
    for (let i = 0; i < workerNames.length; i++) {
      const worker = await prisma.user.create({
        data: {
          name: workerNames[i].name,
          email: workerNames[i].email,
          password: hashedPassword,
          role: 'WORKER',
          department: workerNames[i].dept,
          workerId: `W${String(i + 1).padStart(3, '0')}`,
          phone: workerNames[i].phone,
          nid: workerNames[i].nid,
          gender: i % 2 === 0 ? 'Female' : 'Male',
          joinDate: new Date('2025-03-01'),
          position: 'Senior Operator',
          // Assign first 5 workers to different floors, rest are unassigned
          assignedFloorId: i < 5 ? floors[i].id : null
        }
      });
      workers.push(worker);
    }

    const [worker1, worker2, worker3, worker4, worker5, worker6, worker7, worker8, worker9, worker10] = workers;

    // Create CCTV Cameras - distribute across all floors
    console.log('Creating CCTV cameras...');
    const cctvLocations = ['Entrance', 'Production Area A', 'Production Area B', 'Office Area', 'Storage Room'];
    
    for (let i = 0; i < floors.length; i++) {
      for (let j = 0; j < 2; j++) {
        await prisma.CCTV.create({
          data: {
            name: `CCTV-${String((i * 2 + j + 1)).padStart(3, '0')}`,
            location: `${floors[i].name} - ${cctvLocations[j % cctvLocations.length]}`,
            status: 'active',
            ipAddress: `192.168.${i + 1}.${10 + j}`,
            floorId: floors[i].id
          }
        });
      }
    }

    // Messages will be created by users during application usage
    console.log('✅ Messages module ready for user-created content');

    // Overtime requests will be created by workers during application usage
    console.log('✅ Overtime requests module ready for user-created content');

    console.log('✅ Database seeded successfully!');
    console.log('📝 Production records ready to be added by floor managers via the application.');
  } catch (error) {
    console.error('❌ Seeding error:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

main();

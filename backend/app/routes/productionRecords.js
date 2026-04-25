const express = require('express');
const { PrismaClient } = require('@prisma/client');
const { auth } = require('../middleware/auth');

const router = express.Router();
const prisma = new PrismaClient();

// Shift names
const SHIFT_NAMES = {
  1: 'Morning',
  2: 'Afternoon',
  3: 'Evening',
  4: 'Night'
};

// Create production record
router.post('/', auth, async (req, res) => {
  try {
    const { floorId, date, shift, workersCount, produced, target, qualityRate, notes } = req.body;
    const user = req.user;

    console.log('📝 Production record request:', { floorId, date, shift, workersCount, produced, target, qualityRate, notes });
    console.log('👤 User:', { id: user.id, name: user.name });

    // Validate required fields
    if (!floorId || !date || !shift || workersCount === undefined || produced === undefined || target === undefined) {
      return res.status(400).json({ 
        error: 'Missing required fields: floorId, date, shift, workersCount, produced, target' 
      });
    }

    // Validate shift is 1-4
    if (![1, 2, 3, 4].includes(shift)) {
      return res.status(400).json({ error: 'Shift must be between 1 and 4' });
    }

    // Check if floor exists
    console.log('🔍 Checking for floor with ID:', parseInt(floorId));
    const floor = await prisma.floor.findUnique({ where: { id: parseInt(floorId) } });
    console.log('🏢 Floor found:', floor);
    if (!floor) {
      return res.status(404).json({ error: 'Floor not found' });
    }

    // Check if record already exists for this floor/date/shift
    const existingRecord = await prisma.productionRecord.findUnique({
      where: {
        floorId_date_shift: {
          floorId: parseInt(floorId),
          date: new Date(date),
          shift: parseInt(shift)
        }
      }
    });

    if (existingRecord) {
      return res.status(400).json({ error: 'Production record already exists for this floor, date, and shift' });
    }

    // Calculate efficiency
    const efficiency = target > 0 ? Math.round((produced / target) * 100) : 0;

    // Create production record
    const record = await prisma.productionRecord.create({
      data: {
        floorId: parseInt(floorId),
        date: new Date(date),
        shift: parseInt(shift),
        workersCount: parseInt(workersCount),
        produced: parseInt(produced),
        target: parseInt(target),
        qualityRate: qualityRate ? parseFloat(qualityRate) : null,
        efficiency,
        notes: notes || null,
        recordedBy: user.name,
        recordedById: user.id
      },
      include: {
        floor: true
      }
    });

    res.json(record);
  } catch (error) {
    console.error('Error creating production record:', error);
    res.status(500).json({ error: 'Failed to create production record' });
  }
});

// Get production records by floor
router.get('/floor/:floorId', auth, async (req, res) => {
  try {
    const { floorId } = req.params;
    const { startDate, endDate } = req.query;

    const where = {
      floorId: parseInt(floorId)
    };

    if (startDate && endDate) {
      where.date = {
        gte: new Date(startDate),
        lte: new Date(endDate)
      };
    }

    const records = await prisma.productionRecord.findMany({
      where,
      include: {
        floor: true,
        recordedByUser: { select: { id: true, name: true } }
      },
      orderBy: [{ date: 'desc' }, { shift: 'asc' }]
    });

    // Add shift names
    const recordsWithShiftNames = records.map(record => ({
      ...record,
      shiftName: SHIFT_NAMES[record.shift]
    }));

    res.json(recordsWithShiftNames);
  } catch (error) {
    console.error('Error fetching production records:', error);
    res.status(500).json({ error: 'Failed to fetch production records' });
  }
});

// Get production records for date range (for reports)
router.get('/report/date-range', auth, async (req, res) => {
  try {
    const { startDate, endDate, floorId } = req.query;

    if (!startDate || !endDate) {
      return res.status(400).json({ error: 'startDate and endDate are required' });
    }

    const where = {
      date: {
        gte: new Date(startDate),
        lte: new Date(endDate)
      }
    };

    if (floorId) {
      where.floorId = parseInt(floorId);
    }

    const records = await prisma.productionRecord.findMany({
      where,
      include: {
        floor: true,
        recordedByUser: { select: { id: true, name: true } }
      },
      orderBy: [{ date: 'asc' }, { shift: 'asc' }]
    });

    // Add shift names and calculate summary stats
    const recordsWithShiftNames = records.map(record => ({
      ...record,
      shiftName: SHIFT_NAMES[record.shift]
    }));

    // Calculate summary
    const totalProduced = recordsWithShiftNames.reduce((sum, r) => sum + r.produced, 0);
    const totalTarget = recordsWithShiftNames.reduce((sum, r) => sum + r.target, 0);
    const avgQuality = recordsWithShiftNames
      .filter(r => r.qualityRate !== null)
      .reduce((sum, r) => sum + r.qualityRate, 0) / (recordsWithShiftNames.filter(r => r.qualityRate !== null).length || 1);

    const summary = {
      totalRecords: recordsWithShiftNames.length,
      totalProduced,
      totalTarget,
      overallEfficiency: totalTarget > 0 ? Math.round((totalProduced / totalTarget) * 100) : 0,
      avgQualityRate: recordsWithShiftNames.filter(r => r.qualityRate !== null).length > 0 ? Math.round(avgQuality) : null,
      dateRange: { startDate, endDate }
    };

    res.json({ records: recordsWithShiftNames, summary });
  } catch (error) {
    console.error('Error fetching report data:', error);
    res.status(500).json({ error: 'Failed to fetch report data' });
  }
});

// Get production record by ID
router.get('/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;

    const record = await prisma.productionRecord.findUnique({
      where: { id: parseInt(id) },
      include: {
        floor: true,
        recordedByUser: { select: { id: true, name: true } }
      }
    });

    if (!record) {
      return res.status(404).json({ error: 'Production record not found' });
    }

    res.json({ ...record, shiftName: SHIFT_NAMES[record.shift] });
  } catch (error) {
    console.error('Error fetching production record:', error);
    res.status(500).json({ error: 'Failed to fetch production record' });
  }
});

// Update production record
router.put('/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    const { workersCount, produced, target, qualityRate, notes } = req.body;

    const record = await prisma.productionRecord.findUnique({
      where: { id: parseInt(id) }
    });

    if (!record) {
      return res.status(404).json({ error: 'Production record not found' });
    }

    // Calculate new efficiency if produced/target changed
    const newProduced = produced !== undefined ? produced : record.produced;
    const newTarget = target !== undefined ? target : record.target;
    const efficiency = newTarget > 0 ? Math.round((newProduced / newTarget) * 100) : 0;

    const updated = await prisma.productionRecord.update({
      where: { id: parseInt(id) },
      data: {
        workersCount: workersCount !== undefined ? parseInt(workersCount) : record.workersCount,
        produced: newProduced !== undefined ? parseInt(newProduced) : record.produced,
        target: newTarget !== undefined ? parseInt(newTarget) : record.target,
        qualityRate: qualityRate !== undefined ? parseFloat(qualityRate) : record.qualityRate,
        efficiency,
        notes: notes !== undefined ? notes : record.notes
      },
      include: {
        floor: true,
        recordedByUser: { select: { id: true, name: true } }
      }
    });

    res.json({ ...updated, shiftName: SHIFT_NAMES[updated.shift] });
  } catch (error) {
    console.error('Error updating production record:', error);
    res.status(500).json({ error: 'Failed to update production record' });
  }
});

// Delete production record
router.delete('/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;

    const record = await prisma.productionRecord.findUnique({
      where: { id: parseInt(id) }
    });

    if (!record) {
      return res.status(404).json({ error: 'Production record not found' });
    }

    await prisma.productionRecord.delete({
      where: { id: parseInt(id) }
    });

    res.json({ message: 'Production record deleted successfully' });
  } catch (error) {
    console.error('Error deleting production record:', error);
    res.status(500).json({ error: 'Failed to delete production record' });
  }
});

module.exports = router;

import { Module } from '@nestjs/common';
import { UnitMeasureController } from './unit-measure.controller';
import { UnitMeasureService } from './unit-measure.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UnitMeasure } from './entities/unit-measure.entity';

@Module({
  imports: [TypeOrmModule.forFeature([UnitMeasure])],
  controllers: [UnitMeasureController],
  providers: [UnitMeasureService],
  exports: [UnitMeasureService],
})
export class UnitMeasureModule {}

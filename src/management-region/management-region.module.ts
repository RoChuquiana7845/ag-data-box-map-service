import { Module } from '@nestjs/common';
import { ManagementRegionController } from './management-region.controller';
import { ManagementRegionService } from './management-region.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ManagementRegion } from './entities/management-region.entity';

@Module({
  imports: [TypeOrmModule.forFeature([ManagementRegion])],
  controllers: [ManagementRegionController],
  providers: [ManagementRegionService],
  exports: [ManagementRegionService],
})
export class ManagementRegionModule {}

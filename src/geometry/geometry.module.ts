import { Module } from '@nestjs/common';
import { GeometryService } from './geometry.service';
import { GeometryController } from './geometry.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Geometry } from './entities/geometry.entity';
import { Area } from 'src/area/entities/area.entity';
import { AreaModule } from 'src/area/area.module';

@Module({
  imports: [TypeOrmModule.forFeature([Geometry, Area]), AreaModule],
  providers: [GeometryService],
  controllers: [GeometryController],
  exports: [GeometryService, TypeOrmModule],
})
export class GeometryModule {}

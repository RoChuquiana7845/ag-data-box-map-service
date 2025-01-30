import { Module } from '@nestjs/common';
import { SoilTypeController } from './soil-type.controller';
import { SoilTypeService } from './soil-type.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SoilType } from './entities/soil-type.entity';

@Module({
  imports: [TypeOrmModule.forFeature([SoilType])],
  controllers: [SoilTypeController],
  providers: [SoilTypeService],
  exports: [SoilTypeService],
})
export class SoilTypeModule {}

import { Module } from '@nestjs/common';
import { SamplePointController } from './sample-point.controller';
import { SamplePointService } from './sample-point.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SamplePoint } from './entities/sample-point.entity';

@Module({
  imports: [TypeOrmModule.forFeature([SamplePoint])],
  controllers: [SamplePointController],
  providers: [SamplePointService],
  exports: [SamplePointService],
})
export class SamplePointModule {}

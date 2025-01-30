import { PartialType } from '@nestjs/mapped-types';
import { CreateSamplePointDto } from './create-sample-point.dto';

export class UpdateSamplePointDto extends PartialType(CreateSamplePointDto) {}

import { PartialType } from '@nestjs/mapped-types';
import { CreateSampleGridDto } from './create-sample-grid.dto';

export class UpdateSampleGridDto extends PartialType(CreateSampleGridDto) {}

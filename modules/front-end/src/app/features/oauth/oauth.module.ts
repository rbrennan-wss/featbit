import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { OAuthComponent } from './oauth.component';
import {CoreModule} from "@core/core.module";
import { OAuthRoutingModule } from './oauth-routing.module';

@NgModule({
  declarations: [OAuthComponent],
  imports: [
    CommonModule,
    CoreModule,
    OAuthRoutingModule
  ],
})
export class OAuthModule { }
